CREATE TABLE `audit_history` (
	`id` text PRIMARY KEY NOT NULL,
	`actor_hash` text NOT NULL,
	`created_at` integer NOT NULL,
	`source` text NOT NULL,
	`score` integer NOT NULL,
	`servers` integer NOT NULL,
	`critical` integer NOT NULL,
	`high` integer NOT NULL,
	`medium` integer NOT NULL,
	`to_fix` integer NOT NULL,
	`secure` integer NOT NULL,
	`rule_summary` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `audit_history_actor_created_idx` ON `audit_history` (`actor_hash`,`created_at`);