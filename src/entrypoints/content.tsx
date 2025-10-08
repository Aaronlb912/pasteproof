import { detectPii, DetectionResult } from "@/shared/pii-detector";
import WarningBadge from "@/shared/components/WarningBadge";
import ReactDOM from "react-dom/client";
import type { Root } from "react-dom/client";

export default defineContentScript({
  matches: ["<all_urls>"],

  main(ctx) {
    let activeInput: HTMLInputElement | HTMLTextAreaElement | null = null;
    let badgeUi: IntegratedContentScriptUi<Root> | null = null;

    const positionBadge = (container: HTMLElement) => {
      if (!activeInput) return;
      const rect = activeInput.getBoundingClientRect();
      container.style.position = "fixed";
      container.style.top = `${rect.top}px`;
      container.style.left = `${rect.right + 5}px`;
      container.style.zIndex = "99999";
    };

    const handleDetection = (detections: DetectionResult[]) => {
      if (detections.length > 0) {
        if (!badgeUi) {
          badgeUi = createIntegratedUi(ctx, {
            position: "modal",
            onMount: (container) => {
              const root = ReactDOM.createRoot(container);
              root.render(<WarningBadge detections={detections} />);
              positionBadge(container);
              return root;
            },
            onRemove: (root) => {
              root?.unmount();
            },
          });
          badgeUi.mount();
        } else {
          badgeUi.mounted?.render(<WarningBadge detections={detections} />);
        }
      } else if (badgeUi) {
        badgeUi.remove();
        badgeUi = null;
      }
    };

    const debouncedScan = debounce((text: string) => {
      const results = detectPii(text);
      handleDetection(results);
    }, 500);

    document.addEventListener("focusin", (event) => {
      const target = event.target as HTMLInputElement | HTMLTextAreaElement;

      if (target.tagName !== "INPUT" && target.tagName !== "TEXTAREA") return;

      activeInput = target;

      // Perform an immediate scan on focus
      handleDetection(detectPii(activeInput.value));

      activeInput.addEventListener("input", () => {
        if (activeInput) debouncedScan(activeInput.value);
      });
    });

    document.addEventListener("focusout", (event) => {
      const relatedTarget = event.relatedTarget as Node;
      if (badgeUi?.wrapper.contains(relatedTarget)) {
        return;
      }

      // Otherwise, the user has truly left the input, so we remove the badge.
      if (badgeUi) {
        badgeUi.remove();
        badgeUi = null;
      }
      activeInput = null;
    });

    function debounce(func: (...args: any[]) => void, delay: number) {
      let timeoutId: NodeJS.Timeout;
      return (...args: any[]) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func(...args), delay);
      };
    }
  },
});
