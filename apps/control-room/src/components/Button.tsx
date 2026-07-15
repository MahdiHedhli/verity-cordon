import type { ButtonHTMLAttributes, PropsWithChildren } from "react";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "quiet";
  size?: "small" | "medium";
}

export function Button({
  children,
  className = "",
  variant = "primary",
  size = "medium",
  type = "button",
  ...props
}: PropsWithChildren<ButtonProps>): React.JSX.Element {
  return (
    <button
      className={`button button--${variant} button--${size} ${className}`.trim()}
      type={type}
      {...props}
    >
      {children}
    </button>
  );
}
