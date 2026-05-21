<template>
  <div class="home-root">
    <!-- ── HERO ──────────────────────────────────────────── -->
    <section class="hero-section">
      <div class="hero-inner">
        <div class="hero-logo-row">
          <img
            src="/6g_logo.png"
            alt="PENM Logo"
            class="hero-logo"
            onerror="this.style.display='none'"
          />
        </div>

        <h1 class="hero-title">Privacy Enhanced<br />Network Monitor</h1>

        <p class="hero-tagline">
          Deep inspection and classification of 5G&thinsp;/&thinsp;6G network
          traffic via unsupervised machine learning
        </p>

        <div class="hero-meta">
          <span class="meta-chip">
            <v-icon x-small class="mr-1" style="color: inherit"
              >mdi-school-outline</v-icon
            >
            University of Thessaly
          </span>
          <span class="meta-chip">
            <v-icon x-small class="mr-1" style="color: inherit"
              >mdi-flag-outline</v-icon
            >
            XTRUST-6G
          </span>
          <span class="meta-chip">
            <v-icon x-small class="mr-1" style="color: inherit"
              >mdi-tag-outline</v-icon
            >
            v1.0
          </span>
        </div>

        <v-btn
          color="primary"
          large
          rounded
          class="hero-cta mt-6"
          @click="scrollToScenarios"
        >
          <v-icon left>mdi-arrow-down</v-icon>
          Explore Features
        </v-btn>
      </div>
    </section>

    <!-- ── SCENARIO CARDS ────────────────────────────────── -->
    <section ref="scenarios" class="scenarios-section">
      <div class="scenarios-inner">
        <div class="section-label mb-8">
          <span class="section-label__line" />
          <span class="section-label__text">Use Cases</span>
          <span class="section-label__line" />
        </div>

        <v-row justify="center">
          <!-- Card 1 — PCAP Upload & Analysis -->
          <v-col cols="12" md="6">
            <v-card
              class="scenario-card rounded-xl pa-6 fill-height"
              @click="$router.push('/analyze')"
            >
              <div class="card-icon-wrap mb-4" style="--c: #0ea5e9">
                <v-icon size="36" color="#0ea5e9"
                  >mdi-file-upload-outline</v-icon
                >
              </div>
              <div class="card-badge mb-3">Step 1</div>
              <h2 class="card-title mb-2">PCAP Upload &amp; Analysis</h2>
              <p class="card-desc mb-5">
                Upload a raw <code>.pcap</code> capture file and receive
                per-flow statistics, protocol distribution, an interactive
                network graph, and automated IP role assignments — all in a
                single request.
              </p>
              <div class="card-tags mb-5">
                <span class="tag">Scapy</span>
                <span class="tag">PyShark</span>
                <span class="tag">Network Graph</span>
                <span class="tag">Role Assessment</span>
              </div>
              <v-btn
                color="primary"
                rounded
                small
                class="mt-auto card-btn"
                @click.stop="$router.push('/analyze')"
              >
                <v-icon left small>mdi-arrow-right</v-icon>
                Go to Analyze
              </v-btn>
            </v-card>
          </v-col>

          <!-- Card 2 — Agglomerative Clustering -->
          <v-col cols="12" md="6">
            <v-card
              class="scenario-card rounded-xl pa-6 fill-height"
              @click="$router.push('/analyze')"
            >
              <div class="card-icon-wrap mb-4" style="--c: #8b5cf6">
                <v-icon size="36" color="#8b5cf6"
                  >mdi-chart-scatter-plot</v-icon
                >
              </div>
              <div class="card-badge mb-3">Step 2</div>
              <h2 class="card-title mb-2">Agglomerative Clustering</h2>
              <p class="card-desc mb-5">
                Group IP endpoints by observed traffic behaviour using
                hierarchical clustering with Ward linkage. A rule-based engine
                then infers 5G&thinsp;/&thinsp;6G functional roles — UPF, AMF,
                gNB, UE — for each discovered cluster.
              </p>
              <div class="card-tags mb-5">
                <span class="tag">scikit-learn</span>
                <span class="tag">NetworkX</span>
                <span class="tag">Louvain</span>
                <span class="tag">5G/6G Roles</span>
              </div>
              <v-btn
                color="primary"
                dark
                rounded
                small
                class="mt-auto card-btn"
                @click.stop="$router.push('/analyze')"
              >
                <v-icon left small>mdi-arrow-right</v-icon>
                Upload PCAP first
              </v-btn>
            </v-card>
          </v-col>

          <!-- Card 3 — Real-Time Streaming -->
          <v-col cols="12" md="6">
            <v-card
              class="scenario-card rounded-xl pa-6 fill-height"
              @click="$router.push('/realTime')"
            >
              <div class="card-icon-wrap mb-4" style="--c: #10b981">
                <v-icon size="36" color="#10b981">mdi-access-point</v-icon>
              </div>
              <div class="card-badge mb-3">Live</div>
              <h2 class="card-title mb-2">Real-Time Streaming Analysis</h2>
              <p class="card-desc mb-5">
                Stream a live network capture segment-by-segment and receive
                incremental analysis frames over a Socket.IO WebSocket
                connection. The network graph and statistics panels update in
                real time as each chunk is processed.
              </p>
              <div class="card-tags mb-5">
                <span class="tag">Socket.IO</span>
                <span class="tag">WebSocket</span>
                <span class="tag">Incremental</span>
                <span class="tag">Live Graph</span>
              </div>
              <v-btn
                color="primary"
                rounded
                small
                class="mt-auto card-btn"
                @click.stop="$router.push('/realTime')"
              >
                <v-icon left small>mdi-arrow-right</v-icon>
                Go to Real Time
              </v-btn>
            </v-card>
          </v-col>

          <!-- Card 4 — Continuous Monitoring + History -->
          <v-col cols="12" md="6">
            <v-card class="scenario-card rounded-xl pa-6 fill-height">
              <div class="card-icon-wrap mb-4" style="--c: #f59e0b">
                <v-icon size="36" color="#f59e0b">mdi-monitor-dashboard</v-icon>
              </div>
              <div class="card-badge mb-3">Sensor VM</div>
              <h2 class="card-title mb-2">
                Continuous Monitoring &amp; History
              </h2>
              <p class="card-desc mb-5">
                Monitor live Zeek telemetry streamed from the sensor VM into a
                TimescaleDB hypertable. Anomaly alerts are pushed over
                WebSocket. Revisit all past uploads, generated PCAPs, and
                cluster results from the file history panel.
              </p>
              <div class="card-tags mb-5">
                <span class="tag">Zeek IDS</span>
                <span class="tag">TimescaleDB</span>
                <span class="tag">Alerts</span>
                <span class="tag">History</span>
              </div>
              <div class="d-flex" style="gap: 10px; flex-wrap: wrap">
                <v-btn
                  color="primary"
                  rounded
                  small
                  class="card-btn"
                  @click.stop="$router.push('/continuous_monitoring')"
                >
                  <v-icon left small>mdi-monitor-dashboard</v-icon>
                  Monitoring
                </v-btn>
                <v-btn
                  outlined
                  rounded
                  small
                  class="card-btn"
                  @click.stop="$router.push('/history')"
                >
                  <v-icon left small>mdi-history</v-icon>
                  File History
                </v-btn>
              </div>
            </v-card>
          </v-col>
        </v-row>
      </div>
    </section>

    <!-- ── QUICK STATS BAR ────────────────────────────────── -->
    <section class="stats-section">
      <div class="stats-inner">
        <div v-for="stat in stats" :key="stat.label" class="stat-item">
          <v-icon :color="stat.color" class="mb-2" size="28">{{
            stat.icon
          }}</v-icon>
          <div class="stat-value">{{ stat.value }}</div>
          <div class="stat-label">{{ stat.label }}</div>
        </div>
      </div>
    </section>
  </div>
</template>

<script>
export default {
  data() {
    return {
      stats: [
        {
          icon: "mdi-shield-lock-outline",
          value: "JWT",
          label: "Authentication",
          color: "#0ea5e9",
        },
        {
          icon: "mdi-database-outline",
          value: "TimescaleDB",
          label: "Time-Series Storage",
          color: "#8b5cf6",
        },
        {
          icon: "mdi-brain",
          value: "ML",
          label: "Unsupervised Learning",
          color: "#10b981",
        },
        {
          icon: "mdi-access-point-network",
          value: "5G / 6G",
          label: "Network Functions",
          color: "#f59e0b",
        },
        {
          icon: "mdi-api",
          value: "REST + WS",
          label: "Flask API",
          color: "#ef4444",
        },
        {
          icon: "mdi-open-source-initiative",
          value: "MIT",
          label: "Open Source",
          color: "#64748b",
        },
      ],
    };
  },
  methods: {
    scrollToScenarios() {
      this.$refs.scenarios.scrollIntoView({ behavior: "smooth" });
    },
  },
};
</script>

<style scoped>
/* ── Root ─────────────────────────────────────────────── */
.home-root {
  min-height: 100vh;
}

/* ── Hero ─────────────────────────────────────────────── */
.hero-section {
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 80px 24px 64px;
  text-align: center;
  background: linear-gradient(
    160deg,
    rgba(14, 165, 233, 0.07) 0%,
    transparent 55%,
    rgba(139, 92, 246, 0.06) 100%
  );
  border-bottom: 1px solid var(--border);
}

.hero-inner {
  max-width: 720px;
  width: 100%;
}

.hero-logo-row {
  margin-bottom: 20px;
}

.hero-logo {
  width: 72px;
  height: 72px;
  object-fit: contain;
  filter: drop-shadow(0 0 18px rgba(14, 165, 233, 0.35));
}

.hero-title {
  font-size: clamp(2rem, 5vw, 3rem);
  font-weight: 800;
  line-height: 1.18;
  letter-spacing: -0.02em;
  background: linear-gradient(135deg, var(--metric-value) 0%, #818cf8 100%);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
  margin: 0 0 16px;
}

.hero-tagline {
  font-size: 1.0625rem;
  line-height: 1.65;
  color: var(--text-secondary);
  max-width: 560px;
  margin: 0 auto 20px;
}

.hero-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: center;
}

.meta-chip {
  display: inline-flex;
  align-items: center;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.3px;
  color: var(--text-secondary);
  background: var(--highlight-bg);
  border: 1px solid var(--accent-border);
  border-radius: 20px;
  padding: 4px 12px;
}

.hero-cta {
  font-weight: 700;
  letter-spacing: 0.4px;
}

/* ── Scenarios section ────────────────────────────────── */
.scenarios-section {
  padding: 64px 24px;
}

.scenarios-inner {
  max-width: 960px;
  margin: 0 auto;
}

.section-label {
  display: flex;
  align-items: center;
  gap: 14px;
}

.section-label__line {
  flex: 1;
  height: 1px;
  background: var(--border);
}

.section-label__text {
  font-size: 0.75rem;
  font-weight: 700;
  letter-spacing: 1.8px;
  text-transform: uppercase;
  color: var(--text-muted);
  white-space: nowrap;
}

/* ── Cards ────────────────────────────────────────────── */
.scenario-card {
  cursor: pointer;
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  display: flex;
  flex-direction: column;
  transition: transform 0.18s ease, border-color 0.18s ease,
    box-shadow 0.18s ease;
}

.scenario-card:hover {
  transform: translateY(-4px);
  border-color: var(--accent-border) !important;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.18) !important;
}

.card-icon-wrap {
  width: 60px;
  height: 60px;
  border-radius: 16px;
  background: color-mix(in srgb, var(--c) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--c) 25%, transparent);
  display: flex;
  align-items: center;
  justify-content: center;
}

.card-badge {
  display: inline-block;
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 1.2px;
  text-transform: uppercase;
  color: var(--metric-value);
  background: var(--metric-box-bg);
  border: 1px solid var(--metric-box-border);
  border-radius: 6px;
  padding: 2px 8px;
}

.card-title {
  font-size: 1.2rem;
  font-weight: 700;
  line-height: 1.3;
  color: var(--text-primary, inherit);
}

.card-desc {
  font-size: 0.875rem;
  line-height: 1.7;
  color: var(--text-secondary);
}

.card-desc code {
  font-family: "Courier New", monospace;
  font-size: 0.8rem;
  background: var(--highlight-bg);
  padding: 1px 5px;
  border-radius: 4px;
}

.card-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.tag {
  font-size: 0.7rem;
  font-weight: 600;
  color: var(--text-muted);
  background: var(--highlight-bg);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 2px 10px;
}

.card-btn {
  text-transform: none;
  font-weight: 600;
  letter-spacing: 0.3px;
}

/* ── Stats bar ────────────────────────────────────────── */
.stats-section {
  padding: 40px 24px 56px;
  border-top: 1px solid var(--border);
}

.stats-inner {
  max-width: 960px;
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  justify-content: center;
  gap: 32px;
}

.stat-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  min-width: 100px;
}

.stat-value {
  font-size: 1rem;
  font-weight: 800;
  letter-spacing: 0.2px;
  color: var(--metric-value);
  margin-bottom: 2px;
}

.stat-label {
  font-size: 0.7rem;
  color: var(--text-muted);
  font-weight: 500;
  letter-spacing: 0.3px;
  text-align: center;
}

/* ── Responsive ───────────────────────────────────────── */
@media (max-width: 600px) {
  .hero-section {
    padding: 48px 16px 40px;
  }
  .scenarios-section {
    padding: 40px 12px;
  }
}
</style>
