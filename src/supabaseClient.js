import { createClient } from '@supabase/supabase-js'

// Deux sources : variables du build (VITE_*, ex. développement) ou /config.js servi au lancement par le
// capteur installé (window.__CV_CONFIG__ : URL du projet + clé publique « anon » uniquement).
const runtime = typeof window !== 'undefined' && window.__CV_CONFIG__ ? window.__CV_CONFIG__ : {}
const url = import.meta.env.VITE_SUPABASE_URL || runtime.url
const key = import.meta.env.VITE_SUPABASE_ANON_KEY || runtime.anonKey

export const configured = Boolean(url && key)
export const supabase = configured ? createClient(url, key) : null
