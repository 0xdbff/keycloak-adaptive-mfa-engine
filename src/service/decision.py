import asyncio
import logging
import time
import pandas as pd
import numpy as np
from typing import Dict, Any, List

from src.data.model.auth_process import AuthProcess
from src.utils.auth.device.screen_resolution_checker import ScreenResolutionChecker
from src.data.factory.network_location import NetworkLocationFactory
from src.data.factory.device import DeviceFactory
from src.data.factory.auth_process import AuthProcessFactory
from src.core.redis import get_redis
from src.data.factory import DecisionParamsFactory
from src.data.repository import AuthProcessRepository
from src.data.schema import DecisionRequest, DecisionResponse
from src.utils.synchronization import synchronize_with_distributed_mutex
from src.utils.auth.dependency import tenant_scoped_id


from src.core.config.environment import (
    ACCOUNT_ACTION_DETECTION_ENABLED,
    ACCOUNT_ACTION_EVENT_TYPES,
    ACCOUNT_ACTION_WINDOW_MINUTES,
    ALLOWED_BLACK_WHITE_LIST_PARAMS,
    BAYESIAN_RISK_THRESHOLDS,
    BAYESIAN_BIAS,
    CONCURRENT_SESSION_DETECTION_ENABLED,
    DEFAULT_RISK_LEVEL,
    DROP_DOWN_DECAY_DAYS,
    DROP_DOWN_DECAY_STEPS,
    LOGIN_FAILURE_DETECTION_ENABLED,
    MAX_AUTH_EVENTS,
    MIN_AUTH_EVENTS,
    SCORING_MODE,
    WEIGHT_RISK_BANDS,
    HAZARD_CHANGED_PARAMS_THRESHOLD,
    HAZARD_FAILED_ATTEMPTS_THRESHOLD,
)

from src.service.risk_evaluation import EvalRisk
from src.service.risk_evaluation.checks import (
    process_account_action,
    process_concurrent_session,
    process_login_failure,
)
from src.service.risk_evaluation.checks.inactive_account import (
    resolve_inactive_threshold,
)
from src.service.risk_evaluation.scoring import LogOddsScorer
from src.service.risk_evaluation.explain import (
    friendly_list,
    describe_contributions,
)

_MS_PER_DAY = 86_400_000  # 24 * 60 * 60 * 1000

# Request signals a login may not have; see DecisionService._unavailable_signals.
OPTIONAL_SIGNALS = ("screen_resolution",)


class DecisionService:
    """Service that evaluates the authentication context to produce a risk-level decision.

    This version integrates old whitelist/blacklist checks, hazard detection,
    partial decisions, concurrency locks, and your new parameter-driven approach.

    The final decision is returned as an integer risk level (1, 2, 3, or 4).
    """

    df_user: pd.DataFrame | None
    decision_params: Dict[str, Dict[str, Any]]

    def __init__(self, request_payload: DecisionRequest):
        """Initializes the DecisionService with user request payload and sets up concurrency resources.

        Args:
            request_payload (DecisionRequest):
                The incoming request data containing user, realm, and group context.
        """
        self.risk_levels = [1, int(DEFAULT_RISK_LEVEL), 3, 4]
        self.request_payload = request_payload

        # Ordered, plain-English reasons for the final risk decision, appended at
        # each decision-affecting branch and emitted as one [RISK WHY] line.
        self.explain: List[str] = []

        # A level that a later adjustment must not reduce. Hazard activation sets it
        # when it escalates for "many signals changed at once", because the
        # device/network familiarity adjustment runs afterwards and would otherwise
        # subtract from an escalation that exists precisely for the case where the
        # device stays familiar while everything around it changes. 0 means no floor.
        self.risk_floor: int = 0

        self.redis = get_redis()

    def _why(self, message: str) -> None:
        """Record one plain-English reason step for the final risk decision."""
        # Defensive: some unit tests exercise individual decision methods on an
        # instance built without __init__, so initialise on first use.
        if not hasattr(self, "explain"):
            self.explain = []
        self.explain.append(message)

    def _emit_explanation(self, decision: int, mode: str = "n/a") -> None:
        """Log the accumulated reasons as one [RISK WHY] line.

        Emitted at DEBUG so it is silent in normal operation (LOG_LEVEL=INFO)
        and appears when operators turn on LOG_LEVEL=DEBUG to understand a
        specific decision.

        Deliberately one line, not an indented block. A multi-line record is split
        into separate entries by most log collectors, so the reasons arrive detached
        from the user, realm and risk level that identify them, and a `grep` for a
        user returns the header without the explanation. Reasons are separated by
        " | " because the fragments themselves contain commas and semicolons.
        """
        steps = self.explain or ["(no contributing signals recorded)"]
        logging.debug(
            "[RISK WHY] user=%s realm=%s scoring=%s => final Risk %d because: %s",
            self.request_payload.user_id,
            self.request_payload.realm_id,
            mode,
            decision,
            " | ".join(steps),
        )

    async def __call__(self) -> DecisionResponse:
        """Makes the class instance callable, returning a DecisionResponse.

        Returns:
            DecisionResponse:
                An object containing the numeric riskLevel as determined by `process_decision`.
                risk_level = 1 -> Normal login (no 2FA)
                risk_level = 2 -> OTP login attempt
                risk_level = 3 -> OTP + Authenticator login
                risk_level = 4 -> Login not allowed
        """
        return await self.process_decision()

    async def process_decision(self) -> DecisionResponse:
        """Main entrypoint for fetching the final risk-level decision, with concurrency locking.

        Returns:
            DecisionResponse: The final decision packaged in a schema object.
        """

        @self.__synchronize_user_requests()
        async def __safe_call():
            return await self.__process_decision()

        decision_int = await __safe_call()
        logging.info(
            "Final decision for user_id=%s is risk_level=%d",
            self.request_payload.user_id,
            decision_int,
        )
        return DecisionResponse(riskLevel=decision_int)

    def __synchronize_user_requests(self):
        """Creates a distributed lock for user-specific requests, preventing race conditions."""
        return synchronize_with_distributed_mutex(
            lock_id=tenant_scoped_id(
                self.request_payload.realm_id, self.request_payload.user_id
            ),
            prefix="lock_user",
        )

    async def __process_decision(self) -> int:
        """Performs the protected (locked) decision flow.

        Steps:
        1. Checks for any existing 'auth_process' data in Redis and removes it.
        2. Loads realm/group-based decision parameters.
        3. Retrieves the user's valid authentication records.
        4. Builds a DataFrame of those records.
        5. Runs `EvalRisk` to produce the 'risk_eval_vars' fingerprint.
        6. Invokes `__evaluate_risk` to incorporate partial-decision logic.

        Returns:
            int:
                A numeric risk level: 1, 2, 3, or 4.
        """
        logging.info(
            "Locked function is computing risk-level for user_id=%s",
            self.request_payload.user_id,
        )
        logging.info(
            self.request_payload,
        )
        user_id = self.request_payload.user_id
        auth_process_key = (
            f"auth_process:"
            f"{tenant_scoped_id(self.request_payload.realm_id, user_id)}"
        )

        process_id = await self.redis.get(auth_process_key)
        if process_id is not None:
            logging.debug("Removing existing auth_process data for user_id=%s", user_id)
            await self.redis.delete(auth_process_key)

        process_id = self.request_payload.event_id

        await self.redis.set(
            name=auth_process_key, value=str(process_id), ex=300
        )
        logging.debug(
            f"Created new open auth_process key for user_id={user_id} with 5-minute expiry with value {process_id}",
        )

        self.decision_params = (
            await DecisionParamsFactory.get_active_params_for_realm_group(
                self.request_payload.realm_id, self.request_payload.group_id
            )
        )
        logging.debug(
            "Loaded decision_params for realm=%s group=%s: %s",
            self.request_payload.realm_id,
            self.request_payload.group_id,
            self.decision_params,
        )

        if "__meta" in self.decision_params:
            params_id = self.decision_params["__meta"].get("id")
            logging.debug("Active parameter set id=%s", params_id)

        if not params_id:
            logging.info("Cannot find active parameters configuration")
            raise ValueError("Cannot find active parameters configuration.")

        enabled_params = list(self.decision_params.keys())
        if "__meta" in enabled_params:
            enabled_params.remove("__meta")

        user_valid_auths = await AuthProcessRepository.get_complete_records_for_user(
            user_id=user_id,
            realm_id=self.request_payload.realm_id,
            final_status="LOGIN",
            limit=MAX_AUTH_EVENTS,
        )
        self.len_valid_auths = len(user_valid_auths)
        logging.debug(
            "Fetched %d records for user_id=%s", self.len_valid_auths, user_id
        )

        initial_event_dict = await AuthProcessFactory.build_initial_event_dict(
            self.request_payload
        )

        blacklisted_vars = self.__detect_param_blacklist(initial_event_dict)
        whitelisted_vars = self.__detect_param_whitelist(initial_event_dict)

        if len(user_valid_auths) < MIN_AUTH_EVENTS:
            decision = int(self.risk_levels[2])
            logging.info(
                "Not enough records (%d) for user_id=%s, checking blacklist",
                len(user_valid_auths),
                user_id,
            )
            self._why(
                f"Only {len(user_valid_auths)} successful login(s) are on record "
                f"(at least {MIN_AUTH_EVENTS} are needed to profile this account), "
                f"so there is not enough history to judge it. Applying a cautious "
                f"Risk {decision} until more history builds up."
            )

            _w_len = len(blacklisted_vars) if blacklisted_vars else 0
            if _w_len >= 1:
                logging.info("User is blocked! Increasing Risk Level to 4")
                decision = int(self.risk_levels[3])
                self._why(
                    "A denylisted attribute matched on this login "
                    f"({friendly_list([k for d in blacklisted_vars for k in d])}); "
                    f"raising to Risk {decision}."
                )

            _auth_proc_obj = await AuthProcessFactory.build_preauth_obj(
                request=self.request_payload,
                params_id=params_id,
                auth_context=initial_event_dict,
                risk_eval_vars=None,
                risk_decision=decision,
                device_credibility=0.5,
                net_loc_credibility=0.5,
            )

            _ = await AuthProcessRepository.create_auth_process(_auth_proc_obj)
            self._emit_explanation(decision, mode="history-gate")
            return decision

        self.df_user = pd.DataFrame.from_dict(
            [auth_ctx.auth_context_json for auth_ctx in user_valid_auths]
        ).sort_values(by="event_time", ascending=False)

        if self.df_user is None or self.df_user.empty:
            msg = f"No authentication records available for user_id={user_id}"
            logging.error(msg)
            raise ValueError(msg)

        last_decision = user_valid_auths[0].pre_auth_risk_decision
        second_last_decision = user_valid_auths[1].pre_auth_risk_decision
        previous_event_dict = user_valid_auths[0].auth_context_json
        current_event_dict = initial_event_dict

        logging.debug(
            "Using last_decision=%d second_last_decision=%d for user_id=%s",
            last_decision,
            second_last_decision,
            user_id,
        )

        _risk_eval_vars = EvalRisk(
            df_user=self.df_user,
            last_decision=last_decision,
            second_last_decision=second_last_decision,
            previous_event_dict=previous_event_dict,
            current_event_dict=current_event_dict,
            enabled_params=enabled_params,
            inactive_days=self.decision_params.get("inactive_account", {}).get(
                "inactive_days"
            ),
        ).process()
        logging.debug(
            "Computed risk_eval_vars for user_id=%s => %s", user_id, _risk_eval_vars
        )

        current_screen_resolution = initial_event_dict.get("screen_resolution")
        closest_screen_resolution = self._bucket_screen_resolution(
            current_screen_resolution, user_id
        )
        logging.info(
            "Input Screen Resolution: %s - Closest Screen Resolution: %s",
            current_screen_resolution,
            closest_screen_resolution,
        )
        self.request_payload.screen_resolution = closest_screen_resolution

        (
            device_info_hash,
            network_location_hash,
            valid_auth_process_by_user,
            invalid_auth_process_by_user,
        ) = await asyncio.gather(
            DeviceFactory.identify_from_auth_request(self.request_payload),
            NetworkLocationFactory.identify_from_auth_request(self.request_payload),
            self.__get_valid_auth_process_from_user(user_id),
            self.__get_invalid_auth_process_from_user(user_id),
        )

        logging.debug("Starting credibility compute for device and network location")
        (
            device_credibility,
            net_loc_credibility,
        ) = await asyncio.gather(
            self.__evaluate_device_credibility(
                device_info_hash,
                valid_auth_process_by_user,
                invalid_auth_process_by_user,
            ),
            self.__evaluate_network_loc_credibility(
                network_location_hash,
                valid_auth_process_by_user,
                invalid_auth_process_by_user,
            ),
        )

        logging.debug(
            "Computed credibility. Device: %s - Network Location: %s",
            device_credibility,
            net_loc_credibility,
        )

        self.__evaluate_session_failure_signals(
            risk_eval_vars=_risk_eval_vars,
            valid_processes=valid_auth_process_by_user,
            invalid_processes=invalid_auth_process_by_user,
            current_event=initial_event_dict,
        )

        # E4: flag a login that follows a recent sensitive account action
        # (password/credential/email change). Redis-backed, so evaluated here in
        # the async flow; gated by the global toggle and per-realm enablement to
        # avoid needless scans when the signal is off.
        if ACCOUNT_ACTION_DETECTION_ENABLED and self.__param_is_enabled(
            "recent_account_change"
        ):
            recent_actions = await self.__count_recent_account_actions()
            _risk_eval_vars["recent_account_change"] = process_account_action(
                recent_actions
            )

        decision = await self.__evaluate_risk(
            _risk_eval_vars,
            device_credibility,
            net_loc_credibility,
            blacklisted_vars,
            whitelisted_vars,
        )
        logging.info("Computed final risk-level=%d for user_id=%s", decision, user_id)

        _auth_proc_obj = await AuthProcessFactory.build_preauth_obj(
            request=self.request_payload,
            params_id=params_id,
            auth_context=initial_event_dict,
            risk_eval_vars=_risk_eval_vars,
            risk_decision=decision,
            device_credibility=device_credibility,
            net_loc_credibility=net_loc_credibility,
        )

        _ = await AuthProcessRepository.create_auth_process(_auth_proc_obj)

        self._emit_explanation(decision, mode=getattr(self, "_scoring_mode", "weight"))
        return decision

    def __adjust_for_white_black_list(
        self,
        blacklist_vars: List[dict] | None,
        whitelist_vars: List[dict] | None,
        decision: int,
    ):
        _b_len = len(blacklist_vars) if blacklist_vars else 0
        _w_len = len(whitelist_vars) if whitelist_vars else 0

        if _w_len == 0 and _b_len == 0:
            return decision

        bl_names = friendly_list([k for d in (blacklist_vars or []) for k in d])
        wl_names = friendly_list([k for d in (whitelist_vars or []) for k in d])

        if _b_len > 0 and _w_len == 0:
            logging.debug(
                f"Blacklists len {_b_len} | Whitelists len {_w_len} | Increasing risk, Pre-authentication risk will be 4!"
            )
            self._why(
                f"A denylisted attribute matched ({bl_names}); this is a hard "
                f"override that forces Risk {self.risk_levels[3]} regardless of "
                f"other signals."
            )
            # The rejection level, matching the history-gate path above. A deny list
            # is an administrative block rather than a score, so it is deliberately
            # not configurable: a deny list that only asked for a second factor
            # would silently weaken the one control meant to be absolute.
            return int(self.risk_levels[3])

        if _w_len > 0 and _b_len == 0:
            if decision >= 2:
                logging.debug(
                    f"Blacklists len {_b_len} | Whitelists len {_w_len} | Decrease risk, Max Pre-authentication risk will be 2!"
                )
                self._why(
                    f"An allowlisted attribute matched ({wl_names}); capping the "
                    f"risk at Risk 2 (down from Risk {decision})."
                )
                return 2
            logging.debug(
                f"Blacklists len {_b_len} | Whitelists len {_w_len} | Risk is already 1. Decrease risk, Max Pre-authentication risk will be 1!"
            )
            self._why(
                f"An allowlisted attribute matched ({wl_names}); risk is already "
                f"the lowest, kept at Risk 1."
            )
            return 1

        logging.debug(
            f"Blacklists len {_b_len} | Whitelists len {_w_len} | Increase risk, Min Pre-authentication risk will be 3!"
        )
        self._why(
            f"Both an allowlisted ({wl_names}) and a denylisted ({bl_names}) "
            f"attribute matched; the denylist wins but is tempered to a Risk 3 floor."
        )
        return 3

    async def __evaluate_risk(
        self,
        risk_eval_vars: dict,
        device_credibility: float,
        net_loc_credibility: float,
        blacklisted_vars: list,
        whitelisted_vars: list,
    ) -> int:
        """Computes the final risk level by merging the old short-term detection,
        blacklisting, partial decisions, hazard activation, or fallback logic.

        Args:
            risk_eval_vars (dict):
                The fingerprint containing flags like 'impossible_travel',
                'anonymous_detection', and references to previous/current events.

        Returns:
            int:
                A numeric risk level (1,2,3,4).
        """
        logging.debug("Evaluating risk with old short-term detection and blacklisting.")
        changed_vars = self.__detect_param_change_short_term(risk_eval_vars)

        mode, bias, thresholds = self.__resolve_scoring_config()
        self._scoring_mode = mode
        if mode == "bayesian":
            result = LogOddsScorer(
                decision_params=self.decision_params,
                bias=bias,
                thresholds=thresholds,
            ).score(
                changed_vars=changed_vars,
                device_credibility=device_credibility,
                net_loc_credibility=net_loc_credibility,
                unavailable_vars=self._unavailable_signals(risk_eval_vars),
            )
            logging.info(
                "Bayesian scoring: p(fraud)=%.4f evidence=%.4f bias=%.2f => base Risk %d",
                result.probability,
                result.evidence,
                bias,
                result.risk_level,
            )
            t1, t2, t3 = thresholds
            self._why(
                f"Bayesian model estimated a {result.probability:.0%} chance this "
                f"login is fraudulent. The risk bands are "
                f"<{t1:.0%}=Risk 1, <{t2:.0%}=Risk 2, <{t3:.0%}=Risk 3, "
                f"else Risk 4, so {result.probability:.0%} falls in Risk {result.risk_level}."
            )
            risk_sig, trust_sig = describe_contributions(result.contributions)
            if risk_sig:
                self._why(f"Signals pushing risk up: {risk_sig}.")
            if trust_sig:
                self._why(f"Signals building trust (lowering risk): {trust_sig}.")
            # White/blacklists remain a hard override regardless of scoring mode.
            return self.__adjust_for_white_black_list(
                blacklist_vars=blacklisted_vars,
                whitelist_vars=whitelisted_vars,
                decision=result.risk_level,
            )

        if changed_vars or blacklisted_vars:
            logging.debug(
                "Detected changed_vars=%s blacklisted_vars=%s",
                changed_vars,
                blacklisted_vars,
            )
            if changed_vars:
                self._why(
                    f"{len(changed_vars)} signal(s) differ from this user's norm: "
                    f"{friendly_list(changed_vars)}."
                )
            decision = await self.__hazard_activation(risk_eval_vars, changed_vars)
        else:
            logging.debug(
                "No changes or blacklists found. Falling back to drop_down mechanism."
            )
            decision = self.__drop_down(risk_eval_vars)

        _c = (device_credibility * 0.55) + (net_loc_credibility * 0.45)

        decision = self._adjust_for_credibility(
            c=_c, decision=decision, whitelisted_vars=whitelisted_vars
        )
        decision = self.__adjust_for_white_black_list(
            blacklist_vars=blacklisted_vars,
            whitelist_vars=whitelisted_vars,
            decision=decision,
        )

        return decision

    def __compute_credibility(
        self,
        successes: int,
        failures: int,
        history_scores: List[float],
        min_events: int = MIN_AUTH_EVENTS,
    ) -> float:
        """
        Compute a credibility score ∈ [0,1]:
        - If total < min_events: return prior of 0.2
        - Else: let sr = successes / total
            • Compute signed z = (sr – mean(history)) / std(history)  [ddof=1]
            (or z=0 if len(history)<2 or std=0)
            • Base cred = sr * (1 + z * 0.2)
            • If sr > 0.8, apply 1.2× “high‐performer” bonus
            • Clamp final to [0,1]
        """
        total = successes + failures
        if total < min_events:
            return 0.2

        sr = successes / total

        # signed z-score
        if len(history_scores) >= 2 and np.std(history_scores, ddof=1) > 0:
            u = np.mean(history_scores)
            o = np.std(history_scores, ddof=1)
            z = (sr - u) / o
        else:
            z = 0.0

        cred = sr * (1 + z * 0.2)

        # bonus for very high success
        if sr > 0.8:
            cred *= 1.2

        return min(max(cred, 0.0), 1.0)

    async def __evaluate_device_credibility(
        self, device_hash: str, valid: List[AuthProcess], invalid: List[AuthProcess]
    ) -> float:
        """
        Evaluate the credibility of a device based on historical LOGIN vs LOGIN_ERROR.
        """
        successes = sum(1 for d in valid if d.device_info_hash == device_hash)
        failures = sum(1 for d in invalid if d.device_info_hash == device_hash)

        history = [
            d.device_credibility
            for d in valid + invalid
            if d.device_info_hash == device_hash
        ]
        logging.debug(
            "Evaluating device credibility. Number of successes %s | failures %s | history %s",
            successes,
            failures,
            len(history),
        )
        return self.__compute_credibility(successes, failures, history)

    async def __evaluate_network_loc_credibility(
        self, net_loc_hash: str, valid: List[AuthProcess], invalid: List[AuthProcess]
    ) -> float:
        """
        Same logic, but for network_location_hash and net_loc_credibility.
        """
        successes = sum(1 for d in valid if d.network_location_hash == net_loc_hash)
        failures = sum(1 for d in invalid if d.network_location_hash == net_loc_hash)

        history = [
            d.net_loc_credibility
            for d in valid + invalid
            if d.network_location_hash == net_loc_hash
        ]

        logging.debug(
            "Evaluating network location credibility. Number of successes %s | failures %s | history %s",
            successes,
            failures,
            len(history),
        )
        return self.__compute_credibility(successes, failures, history)

    def __resolve_scoring_config(self) -> tuple:
        """Resolve the effective scoring config: per-realm overrides env defaults.

        Reads the optional scoring_config attached to the active decision params
        (surfaced under __meta) and overlays it on the deployment-level env
        defaults. Returns (mode, bias, thresholds).
        """
        meta = self.decision_params.get("__meta", {}) or {}
        cfg = meta.get("scoring_config") or {}

        mode = cfg.get("mode") or SCORING_MODE
        bias = cfg.get("bias")
        bias = float(bias) if bias is not None else BAYESIAN_BIAS
        thresholds = cfg.get("thresholds") or BAYESIAN_RISK_THRESHOLDS
        return mode, bias, tuple(thresholds)

    def __evaluate_session_failure_signals(
        self,
        risk_eval_vars: dict,
        valid_processes: List[AuthProcess],
        invalid_processes: List[AuthProcess],
        current_event: dict,
    ) -> None:
        """Compute concurrent-session and login-failure signals into risk_eval_vars.

        These behavioural checks operate over the user's success/failure auth-process
        history (not just df_user), so they are evaluated here, where that data has
        already been fetched, rather than inside EvalRisk. Each is gated the same
        way as every other signal: a deployment-level environment toggle AND
        per-realm enablement in ``decision_params``. When triggered it is surfaced
        as a "SUSPICIOUS" flag that both the weight-based and Bayesian scoring
        paths pick up via short-term change detection.
        """
        current_now = current_event.get("event_time")

        if LOGIN_FAILURE_DETECTION_ENABLED and self.__param_is_enabled(
            "login_failure"
        ):
            failures_df = self.__processes_to_df(invalid_processes)
            risk_eval_vars["login_failure"] = process_login_failure(
                failures_df, now_ms=current_now
            )

        if CONCURRENT_SESSION_DETECTION_ENABLED and self.__param_is_enabled(
            "concurrent_session"
        ):
            logins_df = self.__processes_to_df(
                valid_processes, extra_rows=[current_event]
            )
            risk_eval_vars["concurrent_session"] = process_concurrent_session(
                logins_df, now_ms=current_now
            )

    @staticmethod
    def __processes_to_df(
        processes: List[AuthProcess], extra_rows: List[dict] | None = None
    ) -> pd.DataFrame:
        """Build a DataFrame of auth contexts from AuthProcess records.

        Returns an empty frame with the expected columns when there is no data, so
        downstream checks can rely on column presence.
        """
        rows = [
            p.auth_context_json
            for p in (processes or [])
            if getattr(p, "auth_context_json", None)
        ]
        if extra_rows:
            rows = rows + [r for r in extra_rows if r]
        if not rows:
            return pd.DataFrame(columns=["event_time", "ip_address"])
        return pd.DataFrame(rows)

    def __detect_param_change_short_term(self, risk_eval_vars: dict) -> List[str]:
        """Identifies parameters that have changed between previous and current events,
        or that are flagged in the risk_eval_vars.

        This replicates the old short-term detection logic, respecting parameter enablement.

        Args:
            risk_eval_vars (dict):
                The dictionary containing 'previous_event', 'current_event',
                plus flags like 'impossible_travel', 'anonymous_detection', etc.

        Returns:
            list[str]:
                A list of parameter names considered "changed."
        """
        meta_keys = {"__meta"}
        request_variables = (
            set(self.decision_params.keys())
            - meta_keys
            - self._unavailable_signals(risk_eval_vars)
        )

        prev_ev = risk_eval_vars.get("previous_event", {})
        curr_ev = risk_eval_vars.get("current_event", {})

        prev_req = {k: prev_ev[k] for k in (prev_ev.keys() & request_variables)}
        curr_req = {k: curr_ev[k] for k in (curr_ev.keys() & request_variables)}

        prev_set = set(prev_req.items())
        curr_set = set(curr_req.items())
        sym_diff = prev_set ^ curr_set
        changed_variables = list(dict(sym_diff).keys())

        if risk_eval_vars.get("impossible_travel") == "IMPOSSIBLE":
            changed_variables.append("impossible_travel")

        if risk_eval_vars.get("anonymous_detection") == "ANONYMOUS":
            changed_variables.append("anonymous_detection")

        if risk_eval_vars.get("date_time") == "HIGH":
            changed_variables.append("date_time")

        if risk_eval_vars.get("time_interval") == "FORBIDDEN":
            changed_variables.append("time_interval")

        if risk_eval_vars.get("inactive_account") == "INACTIVE":
            changed_variables.append("inactive_account")
            threshold_days = resolve_inactive_threshold(
                self.decision_params.get("inactive_account", {}).get("inactive_days")
            )
            self._why(
                f"This account had not logged in for at least {threshold_days} "
                f"days, which this realm treats as dormant."
            )

        if risk_eval_vars.get("event_cluster_label") == "ANOMALOUS":
            changed_variables.append("event_cluster_label")

        if risk_eval_vars.get("geolocation_cluster_label") == "ANOMALOUS":
            changed_variables.append("geolocation_cluster_label")

        if risk_eval_vars.get("concurrent_session") == "SUSPICIOUS":
            changed_variables.append("concurrent_session")

        if risk_eval_vars.get("login_failure") == "SUSPICIOUS":
            changed_variables.append("login_failure")

        if risk_eval_vars.get("recent_account_change") == "SUSPICIOUS":
            changed_variables.append("recent_account_change")

        # if risk_eval_vars.get("location_consistency") == "FORBIDDEN":
        #     changed_variables.append("location_consistency")

        filtered_vars = []
        for var in changed_variables:
            if self.__param_is_enabled(var):
                filtered_vars.append(var)

        logging.debug(
            "Short-term detection changed_vars=%s \n(filtered from %s)",
            changed_variables,
            filtered_vars,
        )
        return filtered_vars

    def __detect_param_whitelist(self, current_event: dict) -> List[dict]:
        """ """
        logging.info("Starting process to detect whitelist")
        whitelisted = []

        for param in ALLOWED_BLACK_WHITE_LIST_PARAMS:
            if not self.__param_is_enabled(param):
                continue

            whitelist = self.decision_params.get(param, {}).get("whitelist", None)
            curr_val = current_event.get(param)

            if whitelist is not None and curr_val in whitelist:
                whitelisted.append({param: curr_val})

        logging.debug("Whitelisted params=%s", whitelisted)
        return whitelisted

    def __detect_param_blacklist(self, current_event: dict) -> List[dict]:
        """ """
        logging.info("Starting process to detect blacklist")
        blacklisted = []

        for param in ALLOWED_BLACK_WHITE_LIST_PARAMS:
            if not self.__param_is_enabled(param):
                continue

            blacklist = self.decision_params.get(param, {}).get("blacklist", None)
            curr_val = current_event.get(param)
            if blacklist is not None and curr_val in blacklist:
                blacklisted.append({param: curr_val})

        logging.debug("Blacklisted params=%s", blacklisted)
        return blacklisted

    @staticmethod
    def _unavailable_signals(risk_eval_vars: dict) -> set:
        """Signals this login cannot be compared on.

        A login without a screen resolution (a direct grant, or a flow without
        the screen resolution step) cannot be said to have kept or changed it,
        and neither can a login whose previous one had none. Such a signal is
        left out of the change detection and earns no trust. A first login,
        with no previous one at all, keeps the signal as before.
        """
        previous = risk_eval_vars.get("previous_event") or {}
        current = risk_eval_vars.get("current_event") or {}
        unavailable = set()
        for signal in OPTIONAL_SIGNALS:
            if not current.get(signal) or (previous and not previous.get(signal)):
                unavailable.add(signal)
        return unavailable

    @staticmethod
    def _bucket_screen_resolution(current_resolution, user_id) -> str:
        """Classify a screen resolution into its closest common bucket.

        A static method (no instance state, no I/O) rather than inline code
        in `__process_decision`, so it can be tested directly without a real
        DB/Redis session -- the same reasoning `_adjust_for_credibility`
        documents for itself.

        Isolates this one signal: a value `ScreenResolutionChecker` cannot
        interpret degrades only the bucketing (the device fingerprint falls
        back to the raw value, unbucketed) rather than aborting the whole
        evaluation. The request schema already rejects a malformed value
        before it reaches here (see `DecisionRequest.validate_screen_resolution`);
        this is defense in depth for any other path that could still produce
        one, so a single degraded signal never becomes a lost decision.
        """
        if current_resolution is None:
            return None
        try:
            return ScreenResolutionChecker(
                current_resolution=current_resolution
            ).find_closest_resolution()
        except ValueError:
            logging.warning(
                "Could not classify screen_resolution=%r for user_id=%s; "
                "using it unbucketed for this signal only.",
                current_resolution,
                user_id,
            )
            return current_resolution

    def _adjust_for_credibility(
        self, c: float, decision: int, whitelisted_vars=None
    ) -> int:
        """Move the decision according to how familiar the device and network are.

        A method rather than a closure inside __evaluate_risk so it can be tested
        directly. It decides the final level on a large share of logins, and it was
        previously reachable only by driving the whole decision flow.

        Raises to 3 when the context is largely unfamiliar, lowers by one when it is
        fairly familiar, and to 1 when it is very familiar. A lowering is refused if
        it would breach ``self.risk_floor``, which hazard activation sets when it
        escalates for many-signals-changed-at-once.
        """
        before = decision

        if c < 0.3:
            logging.debug(
                f"Authentication context credibility of {c}, assigned high risk!"
            )
            if not whitelisted_vars:
                if decision < 3:
                    logging.debug(
                        f"Corrected assigned risk_level from {decision} to 3!"
                    )
                    decision = 3
                    self._why(
                        f"This device/network is largely unfamiliar (familiarity "
                        f"{c:.2f}, very low); raising from Risk {before} to Risk 3."
                    )
            elif decision < 3:
                self._why(
                    f"Device/network familiarity is very low ({c:.2f}), but an "
                    f"allowlisted attribute is present, so risk is not raised."
                )

        elif c < 0.6:
            logging.debug(
                f"Authentication context credibility of {c}, assigned medium risk!"
            )
        elif c < 0.85:
            logging.debug(
                f"Authentication context credibility of {c}, assigned low risk!"
            )

            if decision >= 2:
                floor = getattr(self, "risk_floor", 0)
                if decision - 1 < floor:
                    self._why(
                        f"This device/network is fairly familiar (familiarity "
                        f"{c:.2f}, high), which would normally lower the risk, but "
                        f"the escalation above is a floor; staying at Risk {decision}."
                    )
                else:
                    logging.debug(
                        f"Corrected assigned risk_level from {decision} to {decision - 1}"
                    )
                    decision -= 1
                    self._why(
                        f"This device/network is fairly familiar (familiarity "
                        f"{c:.2f}, high); lowering from Risk {before} to Risk {decision}."
                    )
        else:
            logging.debug(
                f"Authentication context credibility of {c}, assigned the lowest risk!"
            )

            if decision > 1:
                floor = getattr(self, "risk_floor", 0)
                if floor > 1:
                    self._why(
                        f"This device/network is very familiar (familiarity "
                        f"{c:.2f}, very high), which would normally lower the risk "
                        f"to Risk 1, but the escalation above is a floor; staying "
                        f"at Risk {decision}."
                    )
                else:
                    logging.debug(
                        f"Corrected assigned risk_level from {decision} to 1!"
                    )
                    decision = 1
                    self._why(
                        f"This device/network is very familiar (familiarity "
                        f"{c:.2f}, very high); lowering from Risk {before} to Risk 1."
                    )

        return decision

    async def __hazard_activation(
        self,
        risk_eval_vars: dict,
        changed_vars: List[str],
    ) -> int:
        """Applies hazard activation logic from the old code. If a large number
        of parameters changed, escalate risk immediately. Otherwise, do partial decisions
        and possibly escalate further if the user had high consecutive prior decisions.

        Args:
            risk_eval_vars (dict):
                The fingerprint containing previous and current context, last decisions, etc.
            changed_vars (List[str]):
                List of changed parameters from short-term detection.
            blacklisted_vars (List[str]):
                List of blacklisted parameters from the whitelist checks.

        Returns:
            int:
                The integer risk level (1..4).
        """
        _failed_attempts_24h = await self.__count_failed_attempts_in_last_24h()
        if len(changed_vars) >= HAZARD_CHANGED_PARAMS_THRESHOLD:
            logging.info(
                "Detected >=%s changed parameters, forcing Risk 3.",
                HAZARD_CHANGED_PARAMS_THRESHOLD,
            )

            if _failed_attempts_24h >= HAZARD_FAILED_ATTEMPTS_THRESHOLD:
                logging.info("Multiple login attemps failed, forcing Risk 4.")
                self._why(
                    f"{len(changed_vars)} signals changed at once (a very unfamiliar "
                    f"context) AND {_failed_attempts_24h} failed login attempts in the "
                    f"last 24h; forcing the maximum Risk 4."
                )
                # A floor, not just a value: the familiarity adjustment runs after this
                # and must not subtract from it.
                self.risk_floor = self.risk_levels[3]
                return self.risk_levels[3]

            self._why(
                f"{len(changed_vars)} signals changed at once, which is a very "
                f"unfamiliar context; forcing Risk 3 "
                f"(would be Risk 4 with {HAZARD_FAILED_ATTEMPTS_THRESHOLD}+ recent "
                f"failed attempts; there were {_failed_attempts_24h})."
            )
            self.risk_floor = self.risk_levels[2]
            return self.risk_levels[2]

        # Otherwise proceed with partial decisions
        decision = self.__partial_decisions(changed_vars)
        self._why(
            f"Weighing the changed signals by their configured importance gives a "
            f"tentative Risk {decision}."
        )

        second_last = risk_eval_vars.get("second_last_decision", 0)
        last = risk_eval_vars.get("last_decision", 0)

        if len(changed_vars) < 2 and decision == 3 and last < 3:
            self._why(
                f"Only {len(changed_vars)} signal changed and the previous login was "
                f"low risk (Risk {last}); treating the tentative Risk 3 as noise and "
                f"relaxing to Risk 1."
            )
            return self.risk_levels[1]

        # If last two decisions >=3, and we just produced a 3, escalate to 4
        if (
            decision == 3
            and second_last >= 3
            and last >= 3
            and self.len_valid_auths >= (MIN_AUTH_EVENTS + 2)
            and _failed_attempts_24h >= HAZARD_FAILED_ATTEMPTS_THRESHOLD
        ):
            logging.info(
                "User had two consecutive Risk>=3 and failed multiple login attempts in last 24h."
                + "Escalating new 3 to 4."
            )
            self._why(
                f"The last two logins were already high risk (Risk {last} and "
                f"Risk {second_last}) and there were {_failed_attempts_24h} failed "
                f"attempts in the last 24h; escalating this Risk 3 to Risk 4."
            )
            return self.risk_levels[3]

        return decision

    async def __count_failed_attempts_in_last_24h(self):
        # Failed logins are cached under d:LOGIN_ERROR:* (successful logins use
        # d:LOGIN:*). The "d:" bucket carries a 1-day TTL, so scanning it counts
        # failures within the last 24h. Scanning d:LOGIN:* here would count
        # successes instead, making the hazard-escalation gate fire on login
        # volume rather than on repeated failures.
        _p = (
            f"d:LOGIN_ERROR:"
            f"{tenant_scoped_id(self.request_payload.realm_id, self.request_payload.user_id)}:*"
        )
        _count = 0
        _cursor = 0

        while True:
            _cursor, _keys = await self.redis.scan(cursor=_cursor, match=_p, count=1000)
            _count += len(_keys)
            if _cursor == 0:
                break

        return _count

    async def __count_recent_account_actions(self) -> int:
        """Count the user's sensitive account-change events within the window.

        Sensitive actions (password/credential/email changes) are cached by the
        webhook ingestion under ``<bucket>:<EVENT_TYPE>:<realm_id>:<user_id>:<epoch>``.
        Pick
        the smallest cache bucket that covers the configured window (d=1 day,
        w=7 days, m=31 days) and count events newer than ``now - window``.
        """
        scoped_user = tenant_scoped_id(
            self.request_payload.realm_id, self.request_payload.user_id
        )
        cutoff = time.time() - ACCOUNT_ACTION_WINDOW_MINUTES * 60

        if ACCOUNT_ACTION_WINDOW_MINUTES <= 1440:
            bucket = "d"
        elif ACCOUNT_ACTION_WINDOW_MINUTES <= 7 * 1440:
            bucket = "w"
        else:
            bucket = "m"

        count = 0
        for event_type in ACCOUNT_ACTION_EVENT_TYPES:
            pattern = f"{bucket}:{event_type}:{scoped_user}:*"
            cursor = 0
            while True:
                cursor, keys = await self.redis.scan(
                    cursor=cursor, match=pattern, count=1000
                )
                for key in keys:
                    if isinstance(key, bytes):
                        key = key.decode("utf-8", "ignore")
                    try:
                        event_ts = float(key.rsplit(":", 1)[-1])
                    except (ValueError, IndexError):
                        # Malformed key: count conservatively as in-window.
                        count += 1
                        continue
                    if event_ts >= cutoff:
                        count += 1
                if cursor == 0:
                    break
        return count

    def __partial_decisions(
        self,
        changed_vars: List[str],
    ) -> int:
        """Map the changed 'hazard' parameters to a risk level by cumulative weight.

        Each changed parameter contributes its configured ``weight`` (default 3)
        to a running sum, and that sum is bucketed by ``WEIGHT_RISK_BANDS`` into
        a risk level. This scales monotonically with both the NUMBER of changed
        signals and their SEVERITY: more changes never lower the score, and a
        low-weight change can never dilute a high-weight one. (The previous
        ``ceil(sum / count)`` averaging did both: one weight-3 change scored the
        same as five, and adding a weight-1 change pulled the average down.)

        Args:
            changed_vars (List[str]):
                List of changed parameters.

        Returns:
            int:
                An integer risk level, typically 1..3. (4 may be triggered by
                blacklisting or post-escalation elsewhere.)
        """
        hazard_vars = list(set(changed_vars))
        if not hazard_vars:
            logging.debug("No hazard vars found; defaulting risk to 1.")
            return self.risk_levels[0]

        cumulative_weight = sum(
            self.decision_params.get(param, {}).get("weight", 3)
            for param in hazard_vars
        )

        t2, t3 = WEIGHT_RISK_BANDS
        if cumulative_weight >= t3:
            val = self.risk_levels[2]
        elif cumulative_weight >= t2:
            val = self.risk_levels[1]
        else:
            val = self.risk_levels[0]

        logging.debug(
            "Partial decision cumulative_weight=%s bands=%s => risk %s",
            cumulative_weight,
            (t2, t3),
            val,
        )
        return val

    def __drop_down(self, risk_eval_vars: dict) -> int:
        """Relax risk toward baseline on a clean login (no changes/blacklists).

        Baseline is a single risk-level step down from ``last_decision``. If the previous
        (escalated) login is older than ``DROP_DOWN_DECAY_DAYS``, relax by
        ``DROP_DOWN_DECAY_STEPS`` steps instead so a stale escalation is forgiven
        faster. Risk is always clamped to >= 1.

        A larger step-down requires a valid positive event_time gap between the
        previous and current login; if that gap cannot be computed, the baseline
        one-step drop is used.

        Args:
            risk_eval_vars (dict):
                Fingerprint context. Uses 'last_decision' and the 'event_time' of
                'previous_event' / 'current_event'.

        Returns:
            int: The reduced final risk level (>= 1).
        """
        last = risk_eval_vars.get("last_decision", 3)

        steps = 1
        idle_ms = self.__idle_gap_ms(risk_eval_vars)
        if idle_ms is not None and idle_ms > DROP_DOWN_DECAY_DAYS * _MS_PER_DAY:
            # STEPS>=1 is enforced so a misconfigured DROP_DOWN_DECAY_STEPS<=0
            # can never make an accelerated drop smaller than the baseline
            # one-step drop.
            steps = max(1, DROP_DOWN_DECAY_STEPS)

        new_risk_level = max(1, last - steps)
        logging.debug(
            "Drop-down: last=%s idle_ms=%s steps=%s => %s",
            last,
            idle_ms,
            steps,
            new_risk_level,
        )
        if new_risk_level == last:
            self._why(
                "Clean login — nothing changed from this user's norm, and risk is "
                f"already at the minimum; staying at Risk {new_risk_level}."
            )
        elif steps > 1:
            self._why(
                f"Clean login — nothing changed from this user's norm. The previous "
                f"login was Risk {last} but is stale (idle over {DROP_DOWN_DECAY_DAYS} "
                f"days), so risk is relaxed by {steps} steps to Risk {new_risk_level}."
            )
        else:
            self._why(
                f"Clean login — nothing changed from this user's norm; relaxing one "
                f"step from the previous Risk {last} to Risk {new_risk_level}."
            )
        return new_risk_level

    @staticmethod
    def __idle_gap_ms(risk_eval_vars: dict) -> float | None:
        """Milliseconds between the previous and current login event_time.

        Returns None if the gap cannot be computed (missing/non-numeric
        event_time) or is non-positive (clock skew), signalling the caller to use
        the baseline one-step drop.
        """
        prev = risk_eval_vars.get("previous_event") or {}
        curr = risk_eval_vars.get("current_event") or {}
        try:
            gap = float(curr["event_time"]) - float(prev["event_time"])
        except (KeyError, TypeError, ValueError):
            return None
        return gap if gap > 0 else None

    def __param_is_enabled(self, param_name: str) -> bool:
        """Indicates whether a parameter/signal is enabled in decision_params.

        A signal is enabled when it is present in the resolved ``decision_params``
        and not explicitly disabled. Disabled signals are stripped from
        ``decision_params`` upstream (``format_decision_parameters_to_dict``), so
        an absent param means "off".

        Note: configs carry a ``"disabled"`` flag, not ``"enabled"``. The old
        implementation read a non-existent ``"enabled"`` key and so defaulted to
        True for every param (including absent ones), which let the E4
        recent_account_change signal run even when it was disabled.

        Args:
            param_name (str):
                Name of the parameter to check.

        Returns:
            bool:
                True if the parameter is present and not disabled, else False.
        """
        if param_name not in self.decision_params:
            logging.debug("Parameter='%s' enabled=False (absent)", param_name)
            return False
        conf = self.decision_params.get(param_name, {})
        enabled = not conf.get("disabled", False)
        logging.debug("Parameter='%s' enabled=%s", param_name, enabled)
        return enabled

    async def __get_valid_auth_process_from_user(
        self, user_id: str
    ) -> List[AuthProcess]:
        return await AuthProcessRepository.get_complete_records_for_user(
            final_status="LOGIN",
            user_id=user_id,
            realm_id=self.request_payload.realm_id,
        )

    async def __get_invalid_auth_process_from_user(
        self, user_id: str
    ) -> List[AuthProcess]:
        return await AuthProcessRepository.get_complete_records_for_user(
            final_status="LOGIN_ERROR",
            user_id=user_id,
            realm_id=self.request_payload.realm_id,
        )
