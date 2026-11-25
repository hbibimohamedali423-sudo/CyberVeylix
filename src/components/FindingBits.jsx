import { CONFIDENCE } from '../constants'
import { useI18n } from '../i18n/context.js'
import { cvesOf, cveUrl } from '../lib/findings.js'

// Liens vers la fiche NVD : seules les CVE au format valide deviennent des liens.
export function CveLinks({ row }) {
  const list = cvesOf(row)
  if (!list.length) return '—'
  return list.map((c, i) => {
    const url = cveUrl(c)
    return (
      <span key={c + i} className="cve" dir="ltr">
        {url ? <a href={url} target="_blank" rel="noopener noreferrer">{c.trim().toUpperCase()}</a> : c}
        {i < list.length - 1 ? ', ' : ''}
      </span>
    )
  })
}

export function ConfidenceLabel({ value }) {
  const { t } = useI18n()
  if (!value) return '—'
  return CONFIDENCE.includes(value) ? t(`confidence.${value}`) : value
}
