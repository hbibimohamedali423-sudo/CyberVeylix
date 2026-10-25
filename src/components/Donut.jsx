import { useI18n } from '../i18n/context.js'

export default function Donut({ items }) {
  const { t } = useI18n()
  const total = items.reduce((a, i) => a + i.n, 0)
  const arcs = items.reduce((acc, i) => {
    const pc = total ? (i.n / total) * 100 : 0
    const prev = acc[acc.length - 1]
    const offset = prev ? prev.offset + prev.pc : 0
    return [...acc, { label: i.label, color: i.color, n: i.n, pc, offset }]
  }, [])
  return (
    <svg viewBox="0 0 42 42">
      <circle cx="21" cy="21" r="15.9" fill="none" style={{ stroke: 'var(--track)' }} strokeWidth="5" />
      <g fill="none" strokeWidth="5" transform="rotate(-90 21 21)">
        {arcs.map((a) => (a.n ? (
          <circle key={a.label} cx="21" cy="21" r="15.9" style={{ stroke: a.color }} strokeDasharray={`${a.pc} ${100 - a.pc}`} strokeDashoffset={-a.offset} />
        ) : null))}
      </g>
      <text x="21" y="22" textAnchor="middle" style={{ fill: 'var(--t)' }} fontSize="9" fontWeight="600">{total}</text>
      <text x="21" y="28" textAnchor="middle" style={{ fill: 'var(--m)' }} fontSize="4">{t('common.total')}</text>
    </svg>
  )
}
