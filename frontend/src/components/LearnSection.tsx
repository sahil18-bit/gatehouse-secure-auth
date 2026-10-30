import { useEffect, useState } from "react";
import { getAiSecurity, getOwasp } from "../api";
import type { AiTopic, OwaspItem } from "../types";

type Tab = "owasp" | "ai";

export default function LearnSection() {
  const [tab, setTab] = useState<Tab>("owasp");
  const [edition, setEdition] = useState("");
  const [owasp, setOwasp] = useState<OwaspItem[] | null>(null);
  const [topics, setTopics] = useState<AiTopic[] | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    Promise.all([getOwasp(), getAiSecurity()])
      .then(([o, a]) => {
        setEdition(o.edition);
        setOwasp(o.items);
        setTopics(a);
      })
      .catch(() => setFailed(true));
  }, []);

  return (
    <section className="card learn" aria-labelledby="learn-title">
      <h2 id="learn-title" className="learn__title">
        Learn how this connects to real risks
      </h2>

      <div className="tabs" role="tablist" aria-label="Topic">
        <button
          type="button"
          role="tab"
          id="tab-owasp"
          aria-selected={tab === "owasp"}
          aria-controls="panel-owasp"
          className="tabs__tab"
          onClick={() => setTab("owasp")}
        >
          Web risks
        </button>
        <button
          type="button"
          role="tab"
          id="tab-ai"
          aria-selected={tab === "ai"}
          aria-controls="panel-ai"
          className="tabs__tab"
          onClick={() => setTab("ai")}
        >
          AI and security
        </button>
      </div>

      {failed && <p className="panel__quiet">This content loads from the backend. Start it and refresh.</p>}

      {tab === "owasp" && (
        <div role="tabpanel" id="panel-owasp" aria-labelledby="tab-owasp">
          <p className="learn__intro">
            {edition || "OWASP Top 10"} lists the most critical web application risks. Open one to see how
            this app deals with it.
          </p>
          {(owasp ?? []).map((item) => (
            <details key={item.id} className="risk">
              <summary>
                <span className="risk__id">{item.id}</span>
                {item.name}
              </summary>
              <dl className="risk__body">
                <dt>The risk</dt>
                <dd>{item.risk}</dd>
                <dt>In this app</dt>
                <dd>{item.in_this_app}</dd>
                <dt>How to prevent it</dt>
                <dd>{item.prevention}</dd>
              </dl>
            </details>
          ))}
        </div>
      )}

      {tab === "ai" && (
        <div role="tabpanel" id="panel-ai" aria-labelledby="tab-ai">
          <p className="learn__intro">
            AI can help defend a sign-in system, and it also adds new ways to attack one.
          </p>
          <div className="topics">
            {(topics ?? []).map((topic) => (
              <article key={topic.title} className={`topic topic--${topic.kind}`}>
                <p className="topic__kind">{topic.kind === "application" ? "Helps defend" : "Adds risk"}</p>
                <h3>{topic.title}</h3>
                <p>{topic.summary}</p>
                <p>
                  <strong>Example:</strong> {topic.example}
                </p>
                <p>
                  <strong>Defence:</strong> {topic.defence}
                </p>
              </article>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
