import { Component, Fragment, type ReactNode } from "react";

/** Keep navigation usable if an unexpected render error reaches a page. */
export class PageBoundary extends Component<{ children: ReactNode; resetKey: string }, { failed: boolean; resetKey: string; attempt: number }> {
  state = { failed: false, resetKey: this.props.resetKey, attempt: 0 };

  static getDerivedStateFromError() { return { failed: true }; }
  static getDerivedStateFromProps(props: { resetKey: string }, state: { resetKey: string }) {
    return props.resetKey !== state.resetKey ? { failed: false, resetKey: props.resetKey, attempt: 0 } : null;
  }

  render() {
    if (this.state.failed) return <div className="card" role="alert">
      <h2>This view could not be displayed</h2>
      <p>Try loading it again, or choose another page from the menu.</p>
      <button onClick={() => this.setState((state) => ({ failed: false, attempt: state.attempt + 1 }))}>Try again</button>{" "}
      <a href="/">Go to dashboard</a>
    </div>;
    return <Fragment key={this.state.attempt}>{this.props.children}</Fragment>;
  }
}
