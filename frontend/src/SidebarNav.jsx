import { useEffect } from "react";

const TARGETS = {
  "Threat Intelligence": "Threat Intelligence Feed",
  "Data Collection": "Data Collection",
  "Analyst Queue": "Threat Intelligence Feed",
  "DLP Scanner": "DLP Scanner",
  "Reports": "Reports and Sharing",
};

export default function SidebarNav() {
  useEffect(() => {
    const items = Array.from(document.querySelectorAll(".sidebar .nav-item"));
    const handlers = items.map((el) => {
      const label = el.textContent.trim();
      const fn = () => {
        items.forEach((i) => i.classList.remove("active"));
        el.classList.add("active");
        if (label === "Dashboard") {
          window.scrollTo({ top: 0, behavior: "smooth" });
          return;
        }
        const heading = Array.from(document.querySelectorAll("h3"))
          .find((h) => h.textContent.trim() === TARGETS[label]);
        heading?.scrollIntoView({ behavior: "smooth", block: "start" });
      };
      el.style.cursor = "pointer";
      el.addEventListener("click", fn);
      return [el, fn];
    });
    return () => handlers.forEach(([el, fn]) => el.removeEventListener("click", fn));
  }, []);
  return null;
}
