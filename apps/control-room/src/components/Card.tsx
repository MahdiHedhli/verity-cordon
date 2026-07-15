import type { HTMLAttributes, PropsWithChildren } from "react";

interface CardProps extends HTMLAttributes<HTMLElement> {
  as?: "article" | "section";
}

export function Card({
  as: Element = "section",
  children,
  className = "",
  ...props
}: PropsWithChildren<CardProps>): React.JSX.Element {
  return (
    <Element className={`card ${className}`.trim()} {...props}>
      {children}
    </Element>
  );
}
