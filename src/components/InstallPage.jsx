import { useState } from 'react'
import { useI18n } from '../i18n/context.js'
import './InstallPage.css'

// Page de téléchargement du paquet Windows (releases publiées par .github/workflows/sensor-build.yml).
// Défini ici et non dans constants.js : ce dernier est aussi chargé par les tests Node, sans import.meta.env.
const SENSOR_DOWNLOAD_URL = import.meta.env.VITE_SENSOR_DOWNLOAD_URL
  || 'https://github.com/hbibimohamedali423-sudo/CyberVeylix/releases/latest'

// Commandes Windows : identiques dans toutes les langues (non traduites).
// Elles passent par les fichiers .cmd, qui fonctionnent même si la stratégie d'exécution
// PowerShell du PC est « Restricted » (valeur par défaut de Windows 10/11).
const CMD = {
  install: '.\\install.cmd',
  unattended: '.\\install.cmd -Unattended -ClientName "Client" -AuthorizationRef "Contrat 2026-001"',
  log: 'Get-Content "$env:ProgramData\\CyberVeylix\\Sensor\\sensor.log" -Wait -Tail 20',
  task: 'Get-ScheduledTask -TaskName "CyberVeylix Sensor" | Select-Object TaskName, State',
  vulnscan: '& "$env:ProgramFiles\\CyberVeylix\\Sensor\\vulnscan.cmd"',
  reconfigure: '& "$env:ProgramFiles\\CyberVeylix\\Sensor\\install.cmd" -Reconfigure',
  uninstall: '& "$env:ProgramFiles\\CyberVeylix\\Sensor\\uninstall.cmd"',
  export: '& "$env:ProgramFiles\\CyberVeylix\\Sensor\\uninstall.cmd" -Unattended -ExportTo "$env:USERPROFILE\\Desktop\\cyberveylix-export.zip"',
}

function Command({ id, text, copied, onCopy }) {
  const { t } = useI18n()
  return (
    <div className="cmd">
      {/* Une commande se lit toujours de gauche à droite, y compris en arabe. */}
      <code dir="ltr">{text}</code>
      <button type="button" onClick={() => onCopy(id, text)} aria-label={t('installPage.copyAria')}>
        {copied === id ? t('installPage.copied') : copied === `${id}:err` ? t('installPage.copyFailed') : t('installPage.copy')}
      </button>
    </div>
  )
}

export default function InstallPage() {
  const { t } = useI18n()
  const [copied, setCopied] = useState(null)

  const copy = async (id, text) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(id)
    } catch {
      setCopied(`${id}:err`) // presse-papiers refusé : la commande reste sélectionnable à la main
    }
    setTimeout(() => setCopied((c) => (c === id || c === `${id}:err` ? null : c)), 2000)
  }
  const cmd = (id) => <Command id={id} text={CMD[id]} copied={copied} onCopy={copy} />

  return (
    <div className="card install-page">
      <h3>
        {t('installPage.title')}
        <span className="m" style={{ fontWeight: 400 }}> · {t('installPage.section')}</span>
      </h3>
      <p className="lead">{t('installPage.intro')}</p>

      <section>
        <h4>{t('installPage.reqTitle')}</h4>
        <ul>
          <li>{t('installPage.req1')}</li>
          <li>{t('installPage.req2')}</li>
          <li>{t('installPage.req3')}</li>
        </ul>
        <a className="dl-btn" href={SENSOR_DOWNLOAD_URL} target="_blank" rel="noopener noreferrer">{t('installPage.download')}</a>
        <p className="m">{t('installPage.downloadHint')}</p>
      </section>

      <section>
        <h4>{t('installPage.stepsTitle')}</h4>
        <ol>
          <li>{t('installPage.step1')}</li>
          <li>{t('installPage.step2')}</li>
          <li>{t('installPage.step3')}</li>
          <li>{t('installPage.step4')}</li>
        </ol>
        <p className="m">{t('installPage.cliTitle')}</p>
        {cmd('install')}
        {cmd('unattended')}
      </section>

      <section>
        <h4>{t('installPage.detectsTitle')}</h4>
        <ul className="detects">
          <li><b className="c">●</b> {t('installPage.det1')}</li>
          <li><b className="c">●</b> {t('installPage.det2')}</li>
          <li><b className="c">●</b> {t('installPage.det7')}</li>
          <li><b className="h">●</b> {t('installPage.det8')}</li>
          <li><b className="c">●</b> {t('installPage.det9')}</li>
          <li><b className="h">●</b> {t('installPage.det3')}</li>
          <li><b className="h">●</b> {t('installPage.det4')}</li>
          <li><b className="h">●</b> {t('installPage.det5')}</li>
          <li><b className="mm">●</b> {t('installPage.det6')}</li>
        </ul>
      </section>

      <section>
        <h4>{t('installPage.checkTitle')}</h4>
        {cmd('log')}
        {cmd('task')}
        <p className="m">{t('installPage.vulnscanText')}</p>
        {cmd('vulnscan')}
        <p className="m">{t('installPage.reconfigure')}</p>
        {cmd('reconfigure')}
      </section>

      <section>
        <h4>{t('installPage.uninstallTitle')}</h4>
        <p>{t('installPage.uninstallText')}</p>
        {cmd('uninstall')}
        <p className="m">{t('installPage.exportText')}</p>
        {cmd('export')}
      </section>

      <p className="why m">{t('installPage.whyNoWeb')}</p>
    </div>
  )
}
