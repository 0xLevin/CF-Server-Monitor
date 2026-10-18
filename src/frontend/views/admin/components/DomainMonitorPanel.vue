<template>
  <div class="tab-content" :class="{ active: activeTab === 'domains' }">
    <div class="settings-section domain-monitor">
      <div class="domain-heading">
        <div class="section-title"><span>▸</span> {{ text.title }}</div>
        <button class="btn" type="button" :disabled="loading" @click="loadDomains">{{ text.refresh }}</button>
      </div>

      <form class="domain-form" @submit.prevent="saveDomain">
        <div class="form-group">
          <label class="form-label" for="domain-name">{{ text.domain }}</label>
          <input id="domain-name" v-model.trim="form.domain" class="form-input" type="text" placeholder="example.com" required autocomplete="off" />
        </div>
        <div class="form-group">
          <label class="form-label" for="domain-tls-host">{{ text.tlsHost }}</label>
          <input id="domain-tls-host" v-model.trim="form.tls_host" class="form-input" type="text" placeholder="www.example.com" autocomplete="off" />
        </div>
        <div class="form-group">
          <label class="form-label" for="domain-label">{{ text.label }}</label>
          <input id="domain-label" v-model.trim="form.label" class="form-input" type="text" maxlength="100" autocomplete="off" />
        </div>
        <div class="form-group domain-days">
          <label class="form-label" for="domain-reminder">{{ text.reminderDays }}</label>
          <input id="domain-reminder" v-model.number="form.reminder_days" class="form-input" type="number" min="1" max="90" required />
        </div>
        <label class="domain-enabled"><input v-model="form.enabled" type="checkbox" /> {{ text.enabled }}</label>
        <div class="domain-form-actions">
          <button class="btn btn-primary" type="submit" :disabled="saving">{{ saving ? text.saving : editingId ? text.save : text.add }}</button>
          <button v-if="editingId" class="btn" type="button" @click="resetForm">{{ text.cancel }}</button>
        </div>
      </form>

      <p v-if="error" class="domain-feedback domain-error" role="alert">{{ error }}</p>
      <p v-if="message" class="domain-feedback domain-success" role="status">{{ message }}</p>

      <div class="domain-table-wrap">
        <table class="domain-table">
          <thead>
            <tr>
              <th>{{ text.target }}</th>
              <th>{{ text.registration }}</th>
              <th>{{ text.certificate }}</th>
              <th>{{ text.actions }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="item in domains" :key="item.id" :class="{ 'domain-disabled': !item.enabled }">
              <td :data-label="text.target">
                <div>
                  <strong>{{ item.label || item.domain }}</strong>
                  <span class="domain-subline">{{ item.domain }}</span>
                  <span class="domain-subline">TLS: {{ item.tls_host }}</span>
                  <span v-if="!item.enabled" class="domain-muted">{{ text.paused }}</span>
                </div>
              </td>
              <td :data-label="text.registration">
                <div>
                  <strong :class="expiryClass(item.registration_expires_at, item.reminder_days)">{{ expiryLabel(item.registration_expires_at) }}</strong>
                  <span v-if="item.registration_expires_at" class="domain-subline">{{ remainingLabel(item.registration_expires_at) }}</span>
                  <span v-if="item.registration_error" class="domain-subline domain-error">{{ item.registration_error }}</span>
                  <span class="domain-subline domain-muted">{{ checkedLabel(item.registration_checked_at) }}</span>
                </div>
              </td>
              <td :data-label="text.certificate">
                <div>
                  <strong :class="expiryClass(item.tls_not_after, item.reminder_days)">{{ expiryLabel(item.tls_not_after) }}</strong>
                  <span v-if="item.tls_not_after" class="domain-subline">{{ remainingLabel(item.tls_not_after) }}</span>
                  <span v-if="item.tls_error" class="domain-subline domain-error">{{ item.tls_error }}</span>
                  <span class="domain-subline domain-muted">{{ checkedLabel(item.tls_checked_at) }}</span>
                </div>
              </td>
              <td class="domain-actions" :data-label="text.actions">
                <div class="domain-action-list">
                  <button class="btn" type="button" :disabled="checkingId === item.id" @click="checkNow(item)">{{ checkingId === item.id ? text.checking : text.check }}</button>
                  <button class="btn" type="button" @click="editDomain(item)">{{ text.edit }}</button>
                  <button class="btn btn-red" type="button" :disabled="deletingId === item.id" @click="deleteDomain(item)">{{ text.delete }}</button>
                </div>
              </td>
            </tr>
            <tr v-if="!domains.length">
              <td colspan="4" class="domain-empty">{{ loading ? text.loading : text.empty }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>
</template>

<script setup>
import { computed, ref, watch } from 'vue'
import { http } from '../../../utils/http'
import { currentLang } from '../../../utils/i18n'

const props = defineProps({
  activeTab: { type: String, default: 'servers' },
  selectedApiBase: { type: String, default: '' }
})

const labels = {
  zh: {
    title: '域名监控', refresh: '刷新', domain: '注册域名', tlsHost: '证书主机（留空则使用注册域名）',
    label: '备注名称', reminderDays: '提前提醒（天）', enabled: '启用', saving: '保存中...', save: '保存',
    add: '添加域名', cancel: '取消', target: '监控目标', registration: '注册有效期', certificate: 'SSL 证书',
    actions: '操作', paused: '已暂停', check: '立即检查', checking: '检查中...', edit: '编辑', delete: '删除',
    loading: '加载中...', empty: '还没有监控域名', unknown: '暂无日期', expired: '已过期', days: '天后到期',
    checked: '检查于', never: '尚未检查', saved: '已保存', deleted: '已删除', checkedNow: '检查完成',
    externalPending: '注册信息已检查；证书由定时探针更新',
    deleteConfirm: '确定删除此域名监控？', requestFailed: '请求失败'
  },
  en: {
    title: 'Domain monitoring', refresh: 'Refresh', domain: 'Registered domain', tlsHost: 'TLS hostname (blank uses domain)',
    label: 'Label', reminderDays: 'Remind before (days)', enabled: 'Enabled', saving: 'Saving...', save: 'Save',
    add: 'Add domain', cancel: 'Cancel', target: 'Target', registration: 'Registration expiry', certificate: 'SSL certificate',
    actions: 'Actions', paused: 'Paused', check: 'Check now', checking: 'Checking...', edit: 'Edit', delete: 'Delete',
    loading: 'Loading...', empty: 'No domains monitored', unknown: 'No date', expired: 'Expired', days: 'days left',
    checked: 'Checked', never: 'Not checked yet', saved: 'Saved', deleted: 'Deleted', checkedNow: 'Check complete',
    externalPending: 'Registration checked; TLS is updated by the scheduled probe',
    deleteConfirm: 'Delete this domain monitor?', requestFailed: 'Request failed'
  },
  es: {
    title: 'Monitoreo de dominios', refresh: 'Actualizar', domain: 'Dominio registrado', tlsHost: 'Host TLS (vacío usa el dominio)',
    label: 'Nombre', reminderDays: 'Avisar antes (días)', enabled: 'Activado', saving: 'Guardando...', save: 'Guardar',
    add: 'Agregar dominio', cancel: 'Cancelar', target: 'Objetivo', registration: 'Vencimiento del dominio', certificate: 'Certificado SSL',
    actions: 'Acciones', paused: 'Pausado', check: 'Comprobar', checking: 'Comprobando...', edit: 'Editar', delete: 'Eliminar',
    loading: 'Cargando...', empty: 'No hay dominios', unknown: 'Sin fecha', expired: 'Vencido', days: 'días restantes',
    checked: 'Comprobado', never: 'Aún sin comprobar', saved: 'Guardado', deleted: 'Eliminado', checkedNow: 'Comprobación terminada',
    externalPending: 'Dominio comprobado; el certificado se actualiza con el sondeo programado',
    deleteConfirm: '¿Eliminar este dominio?', requestFailed: 'Error de solicitud'
  }
}

const text = computed(() => labels[currentLang.value] || labels.en)
const domains = ref([])
const probeMode = ref('worker')
const loading = ref(false)
const saving = ref(false)
const checkingId = ref('')
const deletingId = ref('')
const editingId = ref('')
const error = ref('')
const message = ref('')
const blankForm = () => ({ domain: '', tls_host: '', label: '', reminder_days: 30, enabled: true })
const form = ref(blankForm())
const apiOptions = () => ({ baseUrl: props.selectedApiBase })

const resetForm = () => {
  editingId.value = ''
  form.value = blankForm()
}

const loadDomains = async () => {
  if (props.activeTab !== 'domains') return
  loading.value = true
  error.value = ''
  try {
    const result = await http.get('/api/admin/domains', apiOptions())
    if (result.error) throw new Error(result.error)
    domains.value = result.data?.domains || []
    probeMode.value = result.data?.tls_probe_mode || 'worker'
  } catch (cause) {
    error.value = cause.message || text.value.requestFailed
  } finally {
    loading.value = false
  }
}

const saveDomain = async () => {
  saving.value = true
  error.value = ''
  message.value = ''
  try {
    const payload = { ...form.value, tls_host: form.value.tls_host || form.value.domain }
    const result = editingId.value
      ? await http.put(`/api/admin/domains/${editingId.value}`, payload, apiOptions())
      : await http.post('/api/admin/domains', payload, apiOptions())
    if (result.error) throw new Error(result.error)
    const created = !editingId.value
    const id = result.data?.id
    resetForm()
    await loadDomains()
    message.value = text.value.saved
    if (created && id) await checkNow({ id })
  } catch (cause) {
    error.value = cause.message || text.value.requestFailed
  } finally {
    saving.value = false
  }
}

const editDomain = (item) => {
  editingId.value = item.id
  form.value = {
    domain: item.domain,
    tls_host: item.tls_host,
    label: item.label,
    reminder_days: item.reminder_days,
    enabled: Boolean(item.enabled)
  }
  message.value = ''
  error.value = ''
}

const checkNow = async (item) => {
  checkingId.value = item.id
  error.value = ''
  try {
    const result = await http.post(`/api/admin/domains/${item.id}/check`, {}, { ...apiOptions(), timeoutMs: 30000 })
    if (result.error) throw new Error(result.error)
    await loadDomains()
    message.value = probeMode.value === 'external' ? text.value.externalPending : text.value.checkedNow
  } catch (cause) {
    error.value = cause.message || text.value.requestFailed
  } finally {
    checkingId.value = ''
  }
}

const deleteDomain = async (item) => {
  if (!window.confirm(text.value.deleteConfirm)) return
  deletingId.value = item.id
  error.value = ''
  try {
    const result = await http.delete(`/api/admin/domains/${item.id}`, apiOptions())
    if (result.error) throw new Error(result.error)
    if (editingId.value === item.id) resetForm()
    await loadDomains()
    message.value = text.value.deleted
  } catch (cause) {
    error.value = cause.message || text.value.requestFailed
  } finally {
    deletingId.value = ''
  }
}

const expiryLabel = value => value ? new Date(value).toLocaleDateString(currentLang.value) : text.value.unknown
const remainingDays = value => Math.ceil((Number(value) - Date.now()) / 86400000)
const remainingLabel = value => remainingDays(value) <= 0 ? text.value.expired : `${remainingDays(value)} ${text.value.days}`
const expiryClass = (value, reminderDays) => value && remainingDays(value) <= reminderDays ? 'domain-warning' : ''
const checkedLabel = value => value ? `${text.value.checked} ${new Date(value).toLocaleString(currentLang.value)}` : text.value.never

watch(() => [props.activeTab, props.selectedApiBase], ([tab]) => {
  if (tab === 'domains') loadDomains()
}, { immediate: true })
</script>

<style scoped>
.domain-monitor { min-width: 0; }
.domain-heading { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.domain-form { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)) minmax(110px, 140px); gap: 12px; align-items: end; margin: 18px 0 24px; }
.domain-form .form-group { min-width: 0; margin: 0; }
.domain-form .form-input { width: 100%; }
.domain-enabled { display: flex; align-items: center; gap: 6px; min-height: 40px; }
.domain-form-actions { display: flex; gap: 8px; align-items: center; grid-column: span 3; }
.domain-feedback { margin: 8px 0 14px; overflow-wrap: anywhere; }
.domain-error { color: var(--accent-red, #c93f4c); }
.domain-success { color: var(--accent-green, #16844b); }
.domain-table-wrap { overflow-x: auto; }
.domain-table { width: 100%; border-collapse: collapse; text-align: left; }
.domain-table th, .domain-table td { padding: 12px 10px; border-bottom: 1px solid var(--border-color, #3c4950); vertical-align: top; }
.domain-table th { white-space: nowrap; }
.domain-table td { overflow-wrap: anywhere; }
.domain-table td:first-child { min-width: 170px; }
.domain-table td:nth-child(2), .domain-table td:nth-child(3) { min-width: 165px; }
.domain-subline { display: block; font-size: 12px; line-height: 1.5; }
.domain-muted, .domain-disabled { opacity: .68; }
.domain-warning { color: var(--accent-yellow, #d39619); }
.domain-actions { min-width: 240px; white-space: nowrap; }
.domain-actions .btn { margin: 0 5px 5px 0; }
.domain-empty { text-align: center; padding: 28px !important; }
@media (max-width: 850px) {
  .domain-form { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .domain-form-actions { grid-column: span 2; }
}
@media (max-width: 560px) {
  .domain-form { grid-template-columns: 1fr; }
  .domain-form-actions { grid-column: span 1; }
  .domain-table-wrap { overflow: visible; }
  .domain-table, .domain-table tbody, .domain-table tr { display: block; width: 100%; }
  .domain-table thead { display: none; }
  .domain-table tr { padding: 10px 0; border-bottom: 1px solid var(--border-color, #3c4950); }
  .domain-table td { display: grid; grid-template-columns: 92px minmax(0, 1fr); gap: 8px; border: 0; padding: 6px 0; min-width: 0 !important; white-space: normal; }
  .domain-table td::before { content: attr(data-label); font-weight: 600; font-size: 11px; }
  .domain-table td > div { min-width: 0; overflow-wrap: anywhere; }
  .domain-table .domain-empty { display: block; }
  .domain-table .domain-empty::before { content: none; }
  .domain-action-list { display: flex; flex-wrap: wrap; gap: 4px; }
  .domain-actions .btn { margin: 0; }
}
</style>
