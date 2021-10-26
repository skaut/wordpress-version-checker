export function hasStatus(obj: unknown): obj is Record<"status", unknown> {
  return Object.prototype.hasOwnProperty.call(obj, "status");
}
