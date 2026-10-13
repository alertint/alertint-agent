-- SPDX-License-Identifier: FSL-1.1-ALv2

-- Recovery checks every dispatch for an outcome, including completed history.
-- Index the correlated lookup so an empty recovery does not scan the outcome
-- ledger once per historical call. Multiple outcomes and NULL call IDs remain
-- legal; recovery selection and transaction boundaries are unchanged.
CREATE INDEX situation_assessment_attempts_call_idx
    ON situation_assessment_attempts(call_id);
