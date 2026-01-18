// Supabase client — do NOT commit keys to the repo.
// Set these in Netlify env: REACT_APP_SUPABASE_URL, REACT_APP_SUPABASE_ANON_KEY
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.REACT_APP_SUPABASE_URL || '';
const supabaseAnonKey = process.env.REACT_APP_SUPABASE_ANON_KEY || '';

export const supabase = createClient(supabaseUrl, supabaseAnonKey);

export async function fetchNotes() {
  const { data, error } = await supabase.from('notes').select('*').order('id', { ascending: false });
  if (error) throw error;
  return data;
}