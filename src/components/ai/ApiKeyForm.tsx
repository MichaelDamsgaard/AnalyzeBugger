/**
 * API Key Entry Form
 *
 * Shows when no API key is configured, allowing users to enter their key directly.
 */

import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { Key, ExternalLink, AlertCircle, Check, Loader2 } from "lucide-react";

interface ApiKeyFormProps {
  onKeySet: () => void;
}

export function ApiKeyForm({ onKeySet }: ApiKeyFormProps) {
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsSubmitting(true);

    try {
      await invoke("set_api_key", { key: apiKey.trim() });
      onKeySet();
    } catch (err) {
      setError(String(err));
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="h-full flex items-center justify-center bg-bg-primary p-6">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-6">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-accent-purple/20 flex items-center justify-center">
            <Key className="w-8 h-8 text-accent-purple" />
          </div>
          <h2 className="text-lg font-semibold text-text-primary">API Key Required</h2>
          <p className="text-sm text-text-secondary mt-2">
            Enter your Anthropic API key to enable Claude analysis
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="apiKey" className="block text-xs text-text-secondary mb-1">
              API Key
            </label>
            <input
              id="apiKey"
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-ant-api..."
              className="w-full px-3 py-2 text-sm bg-bg-secondary border border-border rounded-lg focus:outline-none focus:border-accent-purple"
              disabled={isSubmitting}
            />
          </div>

          {/* Error message */}
          {error && (
            <div className="flex items-center gap-2 p-2 bg-accent-red/10 border border-accent-red/30 rounded text-xs text-accent-red">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Submit button */}
          <button
            type="submit"
            disabled={!apiKey.trim() || isSubmitting}
            className="w-full py-2 px-4 bg-accent-purple text-white rounded-lg font-medium text-sm hover:bg-accent-purple/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Validating...
              </>
            ) : (
              <>
                <Check className="w-4 h-4" />
                Enable Claude Analysis
              </>
            )}
          </button>
        </form>

        {/* Help link */}
        <div className="mt-6 text-center">
          <a
            href="https://console.anthropic.com/"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-accent-blue hover:underline"
          >
            <ExternalLink className="w-3 h-3" />
            Get an API key from console.anthropic.com
          </a>
        </div>

        {/* Info box */}
        <div className="mt-4 p-3 bg-bg-tertiary rounded-lg text-xs text-text-secondary">
          <p className="font-medium text-text-primary mb-1">Note:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>Your key is stored in memory only (not saved to disk)</li>
            <li>You'll need to re-enter it when you restart the app</li>
            <li>Set ANTHROPIC_API_KEY env var for persistent access</li>
          </ul>
        </div>
      </div>
    </div>
  );
}
