import { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
}

/**
 * Error Boundary component to catch runtime errors in React components.
 * Class component required as React does not support error boundaries in hooks yet.
 *
 * Composition Strategy:
 * - Wraps entire app at root level
 * - Catches errors in child components tree
 * - Displays friendly UI with recovery options
 *
 * Render Optimization:
 * - Catches errors before complete app crash
 * - Prevents blank screen scenarios
 * - Preserves app shell structure
 */
export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null
    };
  }

  static getDerivedStateFromError(_error: Error): Partial<State> {
    // Update state so the next render will show the fallback UI
    return { hasError: true };
  }

  componentDidCatch(_error: Error, errorInfo: ErrorInfo): void {
    // Log the error to console for debugging
    console.error('Error Boundary caught an error:', _error);
    console.error('Error Info:', errorInfo);

    // Store full error info in state for display
    this.setState({
      error: _error,
      errorInfo
    });
  }

  handleReset = (): void => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null
    });
  };

  handleReload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="h-screen w-full bg-background flex items-center justify-center p-6">
          <div className="max-w-md w-full">
            <div className="bg-secondary border border-border/50 rounded-lg p-6 shadow-lg">
              {/* Error Icon */}
              <div className="flex items-center justify-center w-12 h-12 rounded-full bg-destructive/10 mb-4 mx-auto">
                <AlertTriangle className="h-6 w-6 text-destructive" strokeWidth={2} />
              </div>

              {/* Error Title */}
              <h2 className="text-lg font-semibold text-center text-foreground mb-2">
                Something went wrong
              </h2>

              {/* Error Message */}
              <p className="text-sm text-muted-foreground text-center mb-6">
                The application encountered an unexpected error. You can try reloading or resetting the app.
              </p>

              {/* Error Details (Development) */}
              {this.state.error && process.env.NODE_ENV === 'development' && (
                <details className="mb-6">
                  <summary className="text-xs font-medium text-muted-foreground cursor-pointer hover:text-foreground transition-colors mb-2">
                    Error Details
                  </summary>
                  <div className="bg-background rounded p-3 text-xs font-mono overflow-auto max-h-40 border border-border/30">
                    <div className="text-destructive font-semibold mb-2">
                      {this.state.error.toString()}
                    </div>
                    {this.state.errorInfo && (
                      <pre className="text-muted-foreground whitespace-pre-wrap">
                        {this.state.errorInfo.componentStack}
                      </pre>
                    )}
                  </div>
                </details>
              )}

              {/* Action Buttons */}
              <div className="flex gap-3">
                <button
                  onClick={this.handleReset}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition-colors"
                >
                  <RefreshCw size={14} className="opacity-70" />
                  Try Again
                </button>
                <button
                  onClick={this.handleReload}
                  className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 bg-secondary border border-border/50 text-foreground rounded-lg text-sm font-medium hover:bg-secondary/80 transition-colors"
                >
                  Reload App
                </button>
              </div>

              {/* Support Text */}
              <p className="text-xs text-muted-foreground text-center mt-4">
                If this problem persists, please restart the application
              </p>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
