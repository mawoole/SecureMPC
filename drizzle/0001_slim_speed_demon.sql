CREATE TABLE `exception_sync_events` (
	`id` text PRIMARY KEY NOT NULL,
	`space_id` text NOT NULL,
	`record_key` text NOT NULL,
	`actor_hash` text NOT NULL,
	`action` text NOT NULL,
	`created_at` integer NOT NULL,
	`version` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `exception_sync_events_space_created_idx` ON `exception_sync_events` (`space_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `exception_sync_records` (
	`record_key` text PRIMARY KEY NOT NULL,
	`space_id` text NOT NULL,
	`envelope` text NOT NULL,
	`actor_hash` text NOT NULL,
	`updated_at` integer NOT NULL,
	`version` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `exception_sync_space_updated_idx` ON `exception_sync_records` (`space_id`,`updated_at`);