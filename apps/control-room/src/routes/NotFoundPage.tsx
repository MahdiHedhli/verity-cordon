import { Link } from "react-router-dom";
import { Card } from "../components/Card";
import { PageHeader } from "../components/PageHeader";

export function NotFoundPage(): React.JSX.Element {
  return (
    <div className="page">
      <PageHeader
        description="This local Control Room route does not exist."
        eyebrow="404"
        title="View not found"
      />
      <Card>
        <p>Return to the <Link to="/">verified system overview</Link>.</p>
      </Card>
    </div>
  );
}
