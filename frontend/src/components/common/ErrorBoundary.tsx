import { Component, ErrorInfo, ReactNode } from 'react';
import { ShieldAlert, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('CyberRiskOS Page Boundary Error:', error, errorInfo);
  }

  private handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="bg-app-surface border border-app-border rounded-lg p-12 text-center max-w-xl mx-auto my-12 shadow-md">
          <ShieldAlert className="w-12 h-12 text-amber-500 mx-auto mb-4" />
          <h2 className="text-lg font-bold text-text-primary mb-2">Page Loaded Safely</h2>
          <p className="text-xs text-text-secondary mb-6">
            CyberRiskOS safely caught a temporary view render issue. All theme styles, colors, and layout remain preserved.
          </p>
          <button
            onClick={this.handleReset}
            className="px-4 py-2 bg-brand-primary text-white text-xs font-bold rounded hover:bg-blue-700 transition-colors inline-flex items-center"
          >
            <RefreshCw className="w-3.5 h-3.5 mr-2" /> Reload View
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}
