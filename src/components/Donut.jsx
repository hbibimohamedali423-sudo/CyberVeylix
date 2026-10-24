export default function Donut({ items }) {
  const total = items.reduce((a, i) => a + i.n, 0)
  let off = 0
  return (
    <svg viewBox="0 0 42 42">
      <circle cx="21" cy="21" r="15.9" fill="none" stroke="#12304e" strokeWidth="5" />
      <g fill="none" strokeWidth="5" transform="rotate(-90 21 21)">
        {items.map((i) => {
          const pc = total ? (i.n / total) * 100 : 0
          const el = i.n ? <circle key={i.label} cx="21" cy="21" r="15.9" stroke={i.color} strokeDasharray={`${pc} ${100 - pc}`} strokeDashoffset={-off} /> : null
          off += pc
          return el
        })}
      </g>
      <text x="21" y="22" textAnchor="middle" fill="#fff" fontSize="9" fontWeight="600">{total}</text>
      <text x="21" y="28" textAnchor="middle" fill="#8fa6c0" fontSize="4">Total</text>
    </svg>
  )
}
