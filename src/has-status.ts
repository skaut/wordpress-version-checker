export function hasStatus(
  obj: Record<string, unknown>
): obj is Record<"status", unknown> {
  return Object.prototype.hasOwnProperty.call(obj, "status");
}
