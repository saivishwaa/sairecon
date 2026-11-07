import os
from sairecon.core.base import BaseModule


class ScreenshotModule(BaseModule):
    name = "screenshot"
    description = "Visual recon — screenshots of live hosts (gowitness)"
    required_tools = ["gowitness"]

    def __init__(self, *args, output_dir: str = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.output_dir = output_dir or os.path.join(os.getcwd(), "sairecon_screenshots")

    def execute(self):
        if not self.guard_required_tools():
            return self.findings
        os.makedirs(self.output_dir, exist_ok=True)
        self.log(f"Screenshots for {len(self.hosts)} host(s) → {self.output_dir}...")
        self.run(
            ["gowitness", "scan", "file", "-f", "-", "--screenshot-path", self.output_dir, "--write-db"],
            timeout_sec=300,
            input_text="\n".join(f"https://{h}" for h in self.hosts),
        )
        captured = [f for f in os.listdir(self.output_dir) if f.lower().endswith((".png", ".jpg"))]
        self.add_finding(
            title=f"Screenshot Capture — {len(captured)} image(s) saved",
            command="gowitness scan file -f - --screenshot-path <dir>",
            result={"output_dir": self.output_dir, "screenshots_captured": len(captured), "files": captured[:200]},
            severity=None,
        )
        return self.findings
