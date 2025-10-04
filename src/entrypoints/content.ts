// entrypoints/content.ts
export default defineContentScript({
  matches: ['<all_urls>'],
  
  main() {
    console.log('[Paste Proof] Content script loaded and active.');
  },
});