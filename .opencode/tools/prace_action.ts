import { tool } from "@opencode-ai/plugin"
import { spawnSync } from "child_process"

/**
 * Structured PRACE action tool. One declared action_id per call.
 * Talks to the local tracer Unix socket via the Python client helper.
 */
export default tool({
  description:
    "Execute one declared PRACE smoke action (mkdir, write, or delete) through the local tracer. Do not use bash or SSH for cluster file changes.",
  args: {
    action_id: tool.schema
      .string()
      .describe("Declared scenario action id, e.g. mkdir-demo-dir"),
    socket_path: tool.schema
      .string()
      .describe("Absolute path to the tracer Unix socket"),
  },
  async execute(args, context) {
    const result = spawnSync(
      "python3",
      ["-m", "validation.tracer.opencode_bridge", args.socket_path, args.action_id],
      { encoding: "utf-8", cwd: context.worktree },
    )
    if (result.status !== 0) {
      return `REFUSED: ${(result.stderr || result.stdout || "tracer bridge failed").trim()}`
    }
    return (result.stdout || "").trim()
  },
})
