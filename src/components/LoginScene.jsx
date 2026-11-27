import { useEffect, useRef } from 'react'
import * as THREE from 'three'
import { LineSegments2 } from 'three/addons/lines/LineSegments2.js'
import { LineSegmentsGeometry } from 'three/addons/lines/LineSegmentsGeometry.js'
import { LineMaterial } from 'three/addons/lines/LineMaterial.js'

// Scène décorative de la page de connexion : un œil holographique au centre,
// des appareils réseau en 3D (fil de fer) qui tournent autour, et un intrus rouge
// que la pupille suit. Purement visuel : aucune donnée n'est lue ni affichée.
// Chargée à part (React.lazy) pour ne pas alourdir le reste de l'application.

const SKY = 0x33e6f5
const RED = 0xff4d5e
const RX = 5.4
const RZ = 2.6

function buildScene() {
  const scene = new THREE.Scene()
  const mats = []
  const disposables = []
  const track = (o) => { disposables.push(o); return o }

  const lineMat = (color, width = 2, opacity = 1) => {
    const m = track(new LineMaterial({ color, linewidth: width, transparent: true, opacity }))
    mats.push(m)
    return m
  }
  // Remplissage translucide + arêtes nettes : l'effet hologramme.
  const holo = (geo, color = SKY, fill = 0.07, width = 1.8, threshold = 20) => {
    track(geo)
    const g = new THREE.Group()
    g.add(new THREE.Mesh(geo, track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity: fill, depthWrite: false, side: THREE.DoubleSide }))))
    const edges = track(new THREE.EdgesGeometry(geo, threshold))
    g.add(new LineSegments2(track(new LineSegmentsGeometry().fromEdgesGeometry(edges)), lineMat(color, width)))
    return g
  }
  const at = (o, x, y, z, rx = 0, ry = 0, rz = 0) => { o.position.set(x, y, z); o.rotation.set(rx, ry, rz); return o }
  const box = (w, h, d) => new THREE.BoxGeometry(w, h, d)
  const led = (color) => track(new THREE.MeshBasicMaterial({ color }))
  const sphere = (r) => track(new THREE.SphereGeometry(r, 8, 8))

  const camera = () => {
    const g = new THREE.Group()
    g.add(at(holo(box(0.9, 0.42, 0.42)), 0, 0, 0))
    g.add(at(holo(new THREE.CylinderGeometry(0.16, 0.16, 0.14, 20)), 0.5, 0, 0, 0, 0, Math.PI / 2))
    g.add(at(holo(new THREE.CylinderGeometry(0.09, 0.09, 0.06, 16), SKY, 0.5), 0.58, 0, 0, 0, 0, Math.PI / 2))
    g.add(at(holo(box(0.08, 0.5, 0.08)), -0.25, 0.45, 0))
    g.add(at(holo(box(0.5, 0.06, 0.4)), -0.25, 0.72, 0))
    g.add(at(holo(box(1.0, 0.06, 0.5)), 0.05, 0.25, 0))
    return g
  }
  const computer = () => {
    const g = new THREE.Group()
    g.add(at(holo(box(1.3, 0.82, 0.06)), 0, 0.3, 0))
    g.add(at(holo(box(1.16, 0.68, 0.01), SKY, 0.18), 0, 0.3, 0.04))
    g.add(at(holo(box(0.1, 0.3, 0.08)), 0, -0.25, -0.02))
    g.add(at(holo(box(0.6, 0.04, 0.34)), 0, -0.4, 0))
    g.add(at(holo(box(1.0, 0.04, 0.36)), 0, -0.48, 0.42))
    return g
  }
  const phone = () => {
    const g = new THREE.Group()
    g.add(holo(box(0.48, 0.92, 0.07), SKY, 0.06, 1.8, 10))
    g.add(at(holo(box(0.4, 0.76, 0.01), SKY, 0.2), 0, 0.02, 0.04))
    g.add(at(holo(new THREE.CylinderGeometry(0.03, 0.03, 0.02, 12), SKY, 0.6), 0, -0.42, 0.04, Math.PI / 2))
    return g
  }
  const networkSwitch = () => {
    const g = new THREE.Group()
    g.add(holo(box(1.5, 0.22, 0.6)))
    for (let i = 0; i < 8; i++) g.add(at(holo(box(0.11, 0.09, 0.02), SKY, 0.35, 1.2), -0.58 + i * 0.15, 0.02, 0.31))
    for (let i = 0; i < 4; i++) {
      const m = new THREE.Mesh(sphere(0.025), led(i === 2 ? 0xffb23e : 0x7bff8a))
      m.position.set(0.25 + i * 0.12, -0.06, 0.31)
      g.add(m)
    }
    return g
  }
  const wifi = () => {
    const g = new THREE.Group()
    for (const r of [0.25, 0.45, 0.65]) {
      const m = holo(new THREE.TorusGeometry(r, 0.035, 6, 40, Math.PI / 2), SKY, 0.25, 1.6, 30)
      m.rotation.z = Math.PI / 4
      g.add(m)
    }
    g.add(holo(new THREE.SphereGeometry(0.09, 12, 10), SKY, 0.5, 1.4, 30))
    g.add(at(holo(box(0.9, 0.14, 0.5)), 0, -0.32, 0))
    return g
  }
  const router = () => {
    const g = new THREE.Group()
    g.add(holo(box(1.1, 0.24, 0.66)))
    g.add(at(holo(new THREE.CylinderGeometry(0.035, 0.035, 0.8, 8)), -0.38, 0.5, -0.22, 0, 0, 0.15))
    g.add(at(holo(new THREE.CylinderGeometry(0.035, 0.035, 0.8, 8)), 0.38, 0.5, -0.22, 0, 0, -0.15))
    for (let i = 0; i < 5; i++) {
      const m = new THREE.Mesh(sphere(0.025), led(0x7bff8a))
      m.position.set(-0.3 + i * 0.15, 0.02, 0.34)
      g.add(m)
    }
    return g
  }
  const intruder = () => {
    const g = new THREE.Group()
    g.add(at(holo(new THREE.ConeGeometry(0.55, 1.0, 18, 1, true), RED, 0.1, 1.6, 25), 0, -0.25, 0))
    g.add(at(holo(new THREE.SphereGeometry(0.34, 20, 14, 0, Math.PI * 2, 0, Math.PI * 0.62), RED, 0.12, 1.6, 25), 0, 0.42, 0))
    g.add(at(holo(new THREE.CircleGeometry(0.2, 20), 0x220008, 0.95, 1.2, 10), 0, 0.4, 0.25))
    for (const x of [-0.07, 0.07]) {
      const e = new THREE.Mesh(sphere(0.03), led(0xff6b7a))
      e.position.set(x, 0.43, 0.3)
      g.add(e)
    }
    g.add(at(holo(box(0.7, 0.04, 0.44), RED, 0.1), 0, -0.12, 0.34, -0.3))
    return g
  }

  const devices = [camera(), computer(), phone(), networkSwitch(), wifi(), router(), intruder()]
  const orbit = new THREE.Group()
  orbit.position.y = 1.15
  scene.add(orbit)
  devices.forEach((d) => { d.scale.setScalar(1.15); orbit.add(d) })
  const rings = new THREE.Group()
  orbit.add(rings)

  const ring = (rx, rz, opacity, dashed) => {
    const pts = []
    for (let i = 0; i <= 160; i++) {
      const a = (i / 160) * Math.PI * 2
      pts.push([rx * Math.cos(a), -1.45, rz * Math.sin(a)])
    }
    const pos = []
    for (let i = 0; i < pts.length - 1; i++) {
      if (dashed && i % 4 > 1) continue
      pos.push(...pts[i], ...pts[i + 1])
    }
    const geo = track(new LineSegmentsGeometry())
    geo.setPositions(pos)
    rings.add(new LineSegments2(geo, lineMat(SKY, 1.3, opacity)))
  }
  ring(RX, RZ, 0.55, false)
  ring(RX * 1.12, RZ * 1.12, 0.25, true)
  ring(RX * 0.86, RZ * 0.86, 0.18, true)

  // Œil (toujours face à la caméra).
  const eye = new THREE.Group()
  eye.position.set(0, 1.75, 0)
  eye.scale.setScalar(0.7)
  scene.add(eye)
  const lid = (sgn) => {
    const pts = []
    for (let i = 0; i <= 60; i++) {
      const t = (i / 60) * 2 - 1
      pts.push(new THREE.Vector3(t * 2.0, sgn * 0.95 * (1 - t * t) * (1 + 0.1 * (1 - t * t)), 0))
    }
    return pts
  }
  const polyline = (pts, color, width, opacity = 1) => {
    const pos = []
    for (let i = 0; i < pts.length - 1; i++) pos.push(pts[i].x, pts[i].y, pts[i].z, pts[i + 1].x, pts[i + 1].y, pts[i + 1].z)
    const geo = track(new LineSegmentsGeometry())
    geo.setPositions(pos)
    return new LineSegments2(geo, lineMat(color, width, opacity))
  }
  eye.add(polyline(lid(1), SKY, 3))
  eye.add(polyline(lid(-1), SKY, 3))
  eye.add(polyline(lid(1).map((v) => v.clone().multiplyScalar(1.12)), SKY, 1.4, 0.5))
  eye.add(polyline(lid(-1).map((v) => v.clone().multiplyScalar(1.12)), SKY, 1.4, 0.5))
  const shape = new THREE.Shape()
  lid(1).forEach((v, i) => (i ? shape.lineTo(v.x, v.y) : shape.moveTo(v.x, v.y)))
  lid(-1).reverse().forEach((v) => shape.lineTo(v.x, v.y))
  eye.add(new THREE.Mesh(track(new THREE.ShapeGeometry(shape)), track(new THREE.MeshBasicMaterial({ color: 0x06222a, transparent: true, opacity: 0.85 }))))

  const iris = new THREE.Group()
  eye.add(iris)
  const disc = (r1, r2, color, opacity = 1) =>
    new THREE.Mesh(track(new THREE.RingGeometry(r1, r2, 64)), track(new THREE.MeshBasicMaterial({ color, transparent: true, opacity })))
  iris.add(disc(0, 0.78, 0x0a3e48))
  iris.add(disc(0.62, 0.74, SKY))
  iris.add(disc(0.66, 0.7, 0xe2f8ff))
  iris.add(disc(0.48, 0.56, 0x1fa6d8, 0.9))
  const tickGeo = track(new THREE.PlaneGeometry(0.018, 0.09))
  const tickMat = track(new THREE.MeshBasicMaterial({ color: SKY, transparent: true, opacity: 0.7 }))
  for (let i = 0; i < 48; i++) {
    const a = (i / 48) * Math.PI * 2
    const tk = new THREE.Mesh(tickGeo, tickMat)
    tk.position.set(Math.cos(a) * 0.84, Math.sin(a) * 0.84, 0.001)
    tk.rotation.z = a + Math.PI / 2
    iris.add(tk)
  }
  const pupil = new THREE.Group()
  iris.add(pupil)
  pupil.add(disc(0, 0.3, 0x020a0d))
  pupil.add(disc(0.3, 0.34, 0xa8eeff))
  const glint = new THREE.Mesh(track(new THREE.CircleGeometry(0.07, 16)), track(new THREE.MeshBasicMaterial({ color: 0xffffff })))
  glint.position.set(-0.1, 0.1, 0.01)
  pupil.add(glint)

  // Faisceau de l'œil vers l'intrus.
  const beamGeo = track(new LineSegmentsGeometry())
  beamGeo.setPositions([0, 0, 0, 0, 0, 0])
  scene.add(new LineSegments2(beamGeo, lineMat(RED, 1.6, 0.8)))

  return { scene, mats, disposables, devices, rings, eye, iris, beamGeo }
}

export default function LoginScene({ labels }) {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const tagsRef = useRef([])

  useEffect(() => {
    const wrap = wrapRef.current
    const canvas = canvasRef.current
    if (!wrap || !canvas) return undefined

    let renderer
    try {
      renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true })
    } catch {
      // WebGL indisponible : la page de connexion reste utilisable sans la scène.
      wrap.classList.add('is-static')
      return undefined
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2))
    const { scene, mats, disposables, devices, rings, eye, iris, beamGeo } = buildScene()
    const cam = new THREE.PerspectiveCamera(34, 1, 0.1, 100)
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches

    let w = 1
    let h = 1
    let squeeze = 1
    const resize = () => {
      w = Math.max(1, wrap.clientWidth)
      h = Math.max(1, wrap.clientHeight)
      renderer.setSize(w, h, false)
      cam.aspect = w / h
      // Sur écran étroit, l'orbite se resserre ; puis la caméra se place pour que tout tienne
      // en largeur (anneau + libellés) comme en hauteur (œil + appareils).
      squeeze = THREE.MathUtils.clamp(cam.aspect / 1.9, 0.55, 1)
      rings.scale.x = squeeze
      const tanV = Math.tan(THREE.MathUtils.degToRad(cam.fov / 2))
      const halfW = RX * squeeze + 1.4
      const dist = Math.max(halfW / (tanV * cam.aspect), 3.4 / tanV)
      cam.position.set(0, 2.6 * (dist / 13), dist)
      cam.lookAt(0, 0.35, 0)
      cam.updateProjectionMatrix()
      cam.updateMatrixWorld()
      mats.forEach((m) => m.resolution.set(w, h))
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(wrap)

    const tmp = new THREE.Vector3()
    const ip = new THREE.Vector3()
    let t = 0
    let last = performance.now()
    let raf = 0
    const n = devices.length

    const frame = (now) => {
      t += Math.min(0.1, ((now ?? last) - last) / 1000)
      last = now ?? last
      devices.forEach((o, i) => {
        const a = t * 0.45 + (i / n) * Math.PI * 2
        o.position.set(RX * squeeze * Math.cos(a), -1.0 + 0.12 * Math.sin(t * 0.9 + i), RZ * Math.sin(a))
        o.rotation.y = t + i
        o.rotation.x = 0.12 * Math.sin(t * 0.7 + i)
      })
      scene.updateMatrixWorld(true)
      devices.forEach((o, i) => {
        const tag = tagsRef.current[i]
        if (!tag) return
        o.getWorldPosition(tmp)
        const s = tmp.clone().project(cam)
        tag.style.transform = `translate(${((s.x + 1) / 2) * w}px, ${((1 - s.y) / 2) * h + 52}px) translateX(-50%)`
        tag.style.opacity = tmp.z > -1 ? '1' : '0.55'
      })
      // La pupille suit l'intrus.
      devices[n - 1].getWorldPosition(tmp)
      const p = tmp.clone().project(cam)
      const e = eye.position.clone().project(cam)
      const dx = THREE.MathUtils.clamp((p.x - e.x) * 1.6, -1, 1)
      const dy = THREE.MathUtils.clamp((p.y - e.y) * 2.2, -1, 1)
      iris.position.set(dx * 0.62, dy * 0.22, 0.01)
      eye.updateMatrixWorld(true)
      iris.getWorldPosition(ip)
      beamGeo.setPositions([ip.x, ip.y, 0.2, tmp.x, tmp.y + 0.45, tmp.z])
      renderer.render(scene, cam)
      if (!reduce) raf = requestAnimationFrame(frame)
    }
    if (reduce) {
      t = 1.2
      frame(last)
    } else {
      raf = requestAnimationFrame(frame)
    }

    // Pause quand l'onglet est caché (économie de batterie).
    const onVis = () => {
      if (reduce) return
      if (document.hidden) cancelAnimationFrame(raf)
      else { last = performance.now(); raf = requestAnimationFrame(frame) }
    }
    document.addEventListener('visibilitychange', onVis)

    return () => {
      cancelAnimationFrame(raf)
      document.removeEventListener('visibilitychange', onVis)
      ro.disconnect()
      disposables.forEach((d) => d.dispose?.())
      renderer.dispose()
    }
  }, [])

  return (
    <div className="login-hud__scene" ref={wrapRef} aria-hidden="true">
      <canvas ref={canvasRef} />
      {labels.map((l, i) => (
        <span key={l.key} className={`login-hud__tag${l.danger ? ' is-danger' : ''}`} ref={(el) => { tagsRef.current[i] = el }}>
          {l.danger ? '⚠ ' : ''}{l.text}
        </span>
      ))}
    </div>
  )
}
