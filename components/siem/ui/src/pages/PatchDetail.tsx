import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { fetchAssetPatchState } from "../api/patch";
import SectionHeader from "../components/SectionHeader";
import { assets } from "../data/assets";
import { patchItems } from "../data/patch";
import { formatUtcTimestamp } from "../utils/formatters";

const PatchDetail = () => {
  const { patchId } = useParams();
  const patchItem = patchItems.find((item) => item.id === patchId);
  const [patchState, setPatchState] = useState<string | null>(null);

  useEffect(() => {
    if (!patchItem) {
      return undefined;
    }
    const controller = new AbortController();
    const assetId = assets.find((item) => item.name === patchItem.asset)?.id;

    if (!assetId) {
      return () => controller.abort();
    }

    fetchAssetPatchState(assetId, controller.signal)
      .then((state) => {
        const statusLabel = state.status === "patch_blocked" ? "Patch blocked" : "Normal";
        setPatchState(`${statusLabel} · ${formatUtcTimestamp(state.recorded_at)}`);
      })
      .catch(() => {
        setPatchState(null);
      });

    return () => controller.abort();
  }, [patchItem]);

  if (!patchItem) {
    return (
      <section className="page">
        <h1>Patch item not found</h1>
        <p className="page__subtitle">
          The selected patch record is unavailable. Please return to patch management.
        </p>
        <Link className="ghost-button" to="/patch-management">
          Back to patch dashboard
        </Link>
      </section>
    );
  }

  return (
    <section className="page">
      <header className="page__header">
        <div>
          <h1>{patchItem.id}</h1>
          <p className="page__subtitle">{patchItem.asset} · {patchItem.status}</p>
        </div>
        <Link className="ghost-button" to="/patch-management">
          View patch calendar
        </Link>
      </header>

      <div className="grid grid--two">
        <section className="card">
          <SectionHeader
            title="Patch status"
            description="Policy-driven status with ring and scheduling context."
          />
          <ul className="list list--compact">
            <li>
              <span>Ring</span>
              <strong>{patchItem.ring}</strong>
            </li>
            <li>
              <span>Last patch</span>
              <strong>{patchItem.lastPatch}</strong>
            </li>
            <li>
              <span>Next window</span>
              <strong>{patchItem.nextWindow}</strong>
            </li>
            <li>
              <span>Status</span>
              <strong>{patchItem.status}</strong>
            </li>
            {patchState ? (
              <li>
                <span>Asset patch state</span>
                <strong>{patchState}</strong>
              </li>
            ) : null}
          </ul>
        </section>

        <section className="card">
          <SectionHeader
            title="Blockers"
            description="Failures and blockers highlighted above successes."
          />
          <p>{patchItem.blocker ?? "No blockers recorded."}</p>
          <Link className="ghost-button" to="/psa-workflows">
            Raise change ticket
          </Link>
        </section>
      </div>

      <section className="card">
        <SectionHeader
          title="Operational notes"
          description="Captured change context linked to assets and evidence."
        />
        <ul className="list">
          <li>
            <div>
              <strong>Asset owner informed</strong>
              <p>Change advisory notified via PSA.</p>
            </div>
            <span className="badge">Logged</span>
          </li>
          <li>
            <div>
              <strong>Maintenance window</strong>
              <p>{patchItem.nextWindow}</p>
            </div>
            <span className="badge">Scheduled</span>
          </li>
        </ul>
      </section>
    </section>
  );
};

export default PatchDetail;
