/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SELF_HOSTED_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

