<script setup lang="ts">
import Button from "primevue/button";
import InputNumber from "primevue/inputnumber";
import InputText from "primevue/inputtext";
import Checkbox from "primevue/checkbox";
import DataTable from "primevue/datatable";
import Column from "primevue/column";
import Tag from "primevue/tag";
import { onMounted, onUnmounted, reactive, ref, computed } from "vue";

import { useSDK } from "@/plugins/sdk";

const sdk = useSDK();

// ─── State ───────────────────────────────────────────────────────────────────

const status = reactive({
  running: false,
  queued: 0,
  inFlight: 0,
  visited: 0,
  discovered: 0,
  sent: 0,
  ok200: 0,
  redirects: 0,
  errors: 0,
  forms: 0,
  params: 0,
  endpoints: 0,
  scansLaunched: 0,
  requestIdsCollected: 0,
  since: 0,
  last: null as string | null,
  seedHost: null as string | null,
});

const config = reactive({
  concurrency: 10,
  delayMs: 50,
  maxDepth: 5,
  maxRequests: 10000,
  sameHostOnly: true,
  includeRegex: "",
  excludeRegex: "",
  userAgent: "HyperCrawler/3.0 (Weeke-Scanner)",
  autoScan: true,
  scanBatchSize: 15,
  scanBatchDelayMs: 2000,
  scanAggressivity: "medium",
  parseRobotsTxt: true,
  parseSitemapXml: true,
  extractJsUrls: true,
  extractJsonUrls: true,
  submitForms: true,
  followRedirects: true,
  forwardCookies: true,
  seedErrorPages: true,
});

const seedInput = ref("");
const endpoints = ref<any[]>([]);
const statusLog = ref("");
const pollTimer = ref<ReturnType<typeof setInterval> | null>(null);

// ─── Computed ────────────────────────────────────────────────────────────────

const runtime = computed(() => {
  if (!status.since) return "—";
  const ms = Date.now() - status.since;
  const secs = Math.floor(ms / 1000);
  const mins = Math.floor(secs / 60);
  return mins > 0 ? `${mins}m ${secs % 60}s` : `${secs}s`;
});

const rps = computed(() => {
  if (!status.since || !status.sent) return "0";
  const secs = (Date.now() - status.since) / 1000;
  return secs > 0 ? (status.sent / secs).toFixed(1) : "0";
});

// ─── API Calls ───────────────────────────────────────────────────────────────

async function callBackend(method: string, ...args: any[]) {
  try {
    return await (sdk.backend as any)[method](...args);
  } catch (e: any) {
    statusLog.value = `Error: ${e?.message || e}`;
    return null;
  }
}

async function refreshStatus() {
  const res = await callBackend("crawlerGetStatus");
  if (res?.status) {
    Object.assign(status, res.status);
    if (res.status.config) {
      Object.assign(config, res.status.config);
    }
  }
}

async function refreshEndpoints() {
  const res = await callBackend("crawlerGetEndpoints");
  if (res?.endpoints) {
    endpoints.value = res.endpoints;
  }
}

async function onStart() {
  const seeds = seedInput.value
    .split(/[\n,]+/)
    .map((s: string) => s.trim())
    .filter(Boolean);

  const opts: any = { ...config };
  if (!opts.includeRegex) delete opts.includeRegex;
  if (!opts.excludeRegex) delete opts.excludeRegex;
  if (seeds.length) opts.seeds = seeds;

  const res = await callBackend("crawlerStart", opts);
  if (res?.status) {
    Object.assign(status, res.status);
    statusLog.value = "Crawl started!";
    startPolling();
  }
}

async function onStop() {
  const res = await callBackend("crawlerStop");
  if (res?.status) {
    Object.assign(status, res.status);
    statusLog.value = "Crawl stopped.";
    stopPolling();
  }
}

async function onSaveConfig() {
  const opts: any = { ...config };
  if (!opts.includeRegex) delete opts.includeRegex;
  if (!opts.excludeRegex) delete opts.excludeRegex;
  const res = await callBackend("crawlerConfigure", opts);
  if (res?.status) {
    Object.assign(status, res.status);
    statusLog.value = "Config saved.";
  }
}

// ─── Polling ─────────────────────────────────────────────────────────────────

function startPolling() {
  stopPolling();
  pollTimer.value = setInterval(async () => {
    await refreshStatus();
    if (!status.running) {
      stopPolling();
      refreshEndpoints();
    }
  }, 1500);
}

function stopPolling() {
  if (pollTimer.value) {
    clearInterval(pollTimer.value);
    pollTimer.value = null;
  }
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────

onMounted(async () => {
  await refreshStatus();
  if (status.running) startPolling();
  await refreshEndpoints();
});

onUnmounted(() => {
  stopPolling();
});

function severityForSource(source: string) {
  switch (source) {
    case "form": return "warning";
    case "redirect": return "info";
    case "js": return "danger";
    case "robots": return "secondary";
    case "sitemap": return "secondary";
    default: return "primary";
  }
}
</script>

<template>
  <div class="h-full flex flex-col overflow-hidden">
    <!-- Top Controls -->
    <div class="p-4 border-b border-surface-200 dark:border-surface-700 space-y-3">
      <div class="flex items-center gap-3">
        <span class="font-bold text-lg">HyperCrawler</span>
        <Tag v-if="status.running" severity="success" value="Running" />
        <Tag v-else severity="secondary" value="Stopped" />
        <div class="ml-auto flex gap-2">
          <Button
            v-if="!status.running"
            label="Start Crawl"
            icon="fas fa-play"
            severity="success"
            size="small"
            @click="onStart"
          />
          <Button
            v-if="status.running"
            label="Stop"
            icon="fas fa-stop"
            severity="danger"
            size="small"
            @click="onStop"
          />
          <Button
            label="Refresh"
            icon="fas fa-sync"
            severity="secondary"
            size="small"
            text
            @click="refreshStatus(); refreshEndpoints()"
          />
        </div>
      </div>

      <!-- Seed URLs -->
      <div class="flex gap-2 items-start">
        <InputText
          v-model="seedInput"
          placeholder="Seed URLs (comma or newline separated) — leave empty to use Caido history"
          class="flex-1 text-sm"
          :disabled="status.running"
        />
      </div>
    </div>

    <div class="flex-1 min-h-0 flex">
      <!-- Left: Config Panel -->
      <div class="w-72 p-3 border-r border-surface-200 dark:border-surface-700 overflow-y-auto space-y-3 text-sm">
        <div class="font-semibold mb-2">Crawl Settings</div>

        <div class="flex items-center justify-between">
          <label>Concurrency</label>
          <InputNumber v-model="config.concurrency" :min="1" :max="128" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>
        <div class="flex items-center justify-between">
          <label>Delay (ms)</label>
          <InputNumber v-model="config.delayMs" :min="0" :max="10000" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>
        <div class="flex items-center justify-between">
          <label>Max Depth</label>
          <InputNumber v-model="config.maxDepth" :min="1" :max="20" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>
        <div class="flex items-center justify-between">
          <label>Max Requests</label>
          <InputNumber v-model="config.maxRequests" :min="10" :max="100000" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>

        <div class="flex items-center gap-2">
          <Checkbox v-model="config.sameHostOnly" :binary="true" inputId="sameHost" />
          <label for="sameHost">Same host only</label>
        </div>

        <InputText v-model="config.includeRegex" placeholder="Include regex" class="w-full text-xs" />
        <InputText v-model="config.excludeRegex" placeholder="Exclude regex" class="w-full text-xs" />

        <div class="font-semibold mt-3 mb-2">Discovery</div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.parseRobotsTxt" :binary="true" inputId="robots" />
          <label for="robots">Parse robots.txt</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.parseSitemapXml" :binary="true" inputId="sitemap" />
          <label for="sitemap">Parse sitemap.xml</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.extractJsUrls" :binary="true" inputId="jsurls" />
          <label for="jsurls">Extract JS URLs</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.extractJsonUrls" :binary="true" inputId="jsonurls" />
          <label for="jsonurls">Extract JSON API URLs</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.submitForms" :binary="true" inputId="forms" />
          <label for="forms">Submit forms (GET + POST + JSON)</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.followRedirects" :binary="true" inputId="redirects" />
          <label for="redirects">Follow redirects</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.forwardCookies" :binary="true" inputId="cookies" />
          <label for="cookies">Forward session cookies</label>
        </div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.seedErrorPages" :binary="true" inputId="errorpages" />
          <label for="errorpages">Seed error pages (4xx/5xx)</label>
        </div>

        <div class="font-semibold mt-3 mb-2">Scanner Integration</div>
        <div class="flex items-center gap-2">
          <Checkbox v-model="config.autoScan" :binary="true" inputId="autoScan" />
          <label for="autoScan">Auto-scan discovered</label>
        </div>
        <div class="flex items-center justify-between">
          <label>Aggressivity</label>
          <select v-model="config.scanAggressivity" class="text-sm p-1 rounded border border-surface-300 dark:border-surface-600 bg-transparent w-20">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
        </div>
        <div class="flex items-center justify-between">
          <label>Batch size</label>
          <InputNumber v-model="config.scanBatchSize" :min="1" :max="100" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>
        <div class="flex items-center justify-between">
          <label>Batch delay (ms)</label>
          <InputNumber v-model="config.scanBatchDelayMs" :min="500" :max="30000" size="small" class="w-20" inputClass="text-sm p-1 w-full" />
        </div>

        <InputText v-model="config.userAgent" placeholder="User-Agent" class="w-full text-xs mt-2" />

        <Button
          label="Save Config"
          icon="fas fa-save"
          severity="secondary"
          size="small"
          class="w-full mt-2"
          @click="onSaveConfig"
        />
      </div>

      <!-- Right: Stats + Endpoints -->
      <div class="flex-1 flex flex-col overflow-hidden">
        <!-- Stats Bar -->
        <div class="p-3 border-b border-surface-200 dark:border-surface-700 grid grid-cols-4 gap-2 text-sm">
          <div class="text-center">
            <div class="text-2xl font-bold text-primary">{{ status.visited }}</div>
            <div class="text-xs opacity-60">Visited</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-green-500">{{ status.endpoints }}</div>
            <div class="text-xs opacity-60">Endpoints</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-yellow-500">{{ status.forms }}</div>
            <div class="text-xs opacity-60">Forms</div>
          </div>
          <div class="text-center">
            <div class="text-2xl font-bold text-blue-500">{{ status.scansLaunched }}</div>
            <div class="text-xs opacity-60">Auto-Scans</div>
          </div>
        </div>

        <!-- Secondary Stats -->
        <div class="p-2 border-b border-surface-200 dark:border-surface-700 flex gap-4 text-xs opacity-70 flex-wrap">
          <span>Queued: {{ status.queued }}</span>
          <span>In-flight: {{ status.inFlight }}</span>
          <span>Sent: {{ status.sent }}</span>
          <span>200s: {{ status.ok200 }}</span>
          <span>Redirects: {{ status.redirects }}</span>
          <span>Errors: {{ status.errors }}</span>
          <span>Params: {{ status.params }}</span>
          <span>Collected IDs: {{ status.requestIdsCollected }}</span>
          <span>Runtime: {{ runtime }}</span>
          <span>RPS: {{ rps }}</span>
          <span v-if="status.seedHost">Host: {{ status.seedHost }}</span>
        </div>

        <!-- Endpoints Table -->
        <div class="flex-1 min-h-0 overflow-auto">
          <DataTable
            :value="endpoints"
            :rows="100"
            :paginator="endpoints.length > 100"
            scrollable
            scrollHeight="flex"
            class="text-sm"
            stripedRows
            size="small"
          >
            <Column field="method" header="Method" style="width: 80px">
              <template #body="{ data }">
                <Tag
                  :value="data.method"
                  :severity="data.method === 'POST' ? 'warning' : 'info'"
                  class="text-xs"
                />
              </template>
            </Column>
            <Column field="url" header="URL" style="min-width: 300px">
              <template #body="{ data }">
                <span class="font-mono text-xs break-all">{{ data.url }}</span>
              </template>
            </Column>
            <Column field="params" header="Parameters" style="min-width: 150px">
              <template #body="{ data }">
                <div class="flex flex-wrap gap-1">
                  <Tag
                    v-for="p in data.params"
                    :key="p"
                    :value="p"
                    severity="primary"
                    class="text-xs"
                  />
                  <span v-if="!data.params?.length" class="opacity-40">—</span>
                </div>
              </template>
            </Column>
            <Column field="source" header="Source" style="width: 100px">
              <template #body="{ data }">
                <Tag
                  :value="data.source"
                  :severity="severityForSource(data.source)"
                  class="text-xs"
                />
              </template>
            </Column>
            <template #empty>
              <div class="text-center py-8 opacity-50">
                No endpoints discovered yet. Start a crawl to discover forms, links, and parameters.
              </div>
            </template>
          </DataTable>
        </div>

        <!-- Status Log -->
        <div v-if="statusLog" class="p-2 bg-surface-100 dark:bg-surface-800 text-xs border-t border-surface-200 dark:border-surface-700">
          {{ statusLog }}
        </div>
        <div v-if="status.last" class="p-2 bg-surface-50 dark:bg-surface-900 text-xs border-t border-surface-200 dark:border-surface-700 font-mono truncate opacity-60">
          Last: {{ status.last }}
        </div>
      </div>
    </div>
  </div>
</template>
