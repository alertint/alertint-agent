-- SPDX-License-Identifier: FSL-1.1-ALv2

ALTER TABLE situations ADD COLUMN supersede_streak INTEGER NOT NULL DEFAULT 0
    CHECK (supersede_streak >= 0);
ALTER TABLE situations ADD COLUMN lease_protected INTEGER NOT NULL DEFAULT 0
    CHECK (lease_protected IN (0, 1));
