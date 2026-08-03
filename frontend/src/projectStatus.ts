import type { ProjectStatus } from "./types";

export const PROJECT_STATUS_ORDER: ProjectStatus[] = [
  "active",
  "freeze",
  "handover_to_development",
  "vulnerability_recheck",
  "completed",
  "archived",
];
