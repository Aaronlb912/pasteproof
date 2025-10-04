// entrypoints/content.ts
import { detectPii } from '../shared/pii-detector';

export default defineContentScript({
  matches: ['<all_urls>'],

  main() {
    console.log('[Paste Proof] Content script active and listening.');

    // A simple debounce function to prevent scanning on every single keystroke
    const debounce = (func: (...args: any[]) => void, delay: number) => {
      let timeoutId: NodeJS.Timeout;
      return (...args: any[]) => {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func(...args), delay);
      };
    };

    const scanForPii = (element: HTMLInputElement | HTMLTextAreaElement) => {
      const text = element.value;
      if (!text) return; // Don't scan empty fields

      const results = detectPii(text);
      if (results.length > 0) {
        // For now, we just log the results.
        // In the next step, this is where we'll show a UI badge.
        console.warn('[Paste Proof] PII Detected!', {
          field: element,
          detections: results,
        });
      }
    };

    // Create a debounced version of our scanner
    const debouncedScan = debounce(scanForPii, 700);

    // Attach listeners to all input and textarea elements on the page
    document.querySelectorAll('input, textarea').forEach((element) => {
      const el = element as HTMLInputElement | HTMLTextAreaElement;
      
      // Listen for text being typed or pasted
      el.addEventListener('input', () => debouncedScan(el));
      el.addEventListener('paste', () => scanForPii(el)); // Scan immediately on paste
    });
  },
});