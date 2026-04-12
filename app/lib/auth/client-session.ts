const TOKEN_STORAGE_KEY = "sentinel_token";

export const clientSessionStorage = {
  readToken() {
    if (typeof window === "undefined") {
      return null;
    }

    return window.localStorage.getItem(TOKEN_STORAGE_KEY);
  },
  saveToken(token: string) {
    if (typeof window === "undefined") {
      return;
    }

    window.localStorage.setItem(TOKEN_STORAGE_KEY, token);
  },
  clearToken() {
    if (typeof window === "undefined") {
      return;
    }

    window.localStorage.removeItem(TOKEN_STORAGE_KEY);
  },
};
