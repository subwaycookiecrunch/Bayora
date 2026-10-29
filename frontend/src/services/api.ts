import {
  Evaluation,
  DefenseRule,
  AttackScenario,
  AuditBlock,
  AuditVerificationResult,
  LoopResult,
  SystemTelemetry,
  SecurityPolicy,
  UserRole
} from '../types';

const API_BASE = '/api/v1';

// Token storage
let currentToken = localStorage.getItem('bayora_token') || '';
let currentRole: UserRole = (localStorage.getItem('bayora_role') as UserRole) || 'admin';
let currentUsername = localStorage.getItem('bayora_username') || 'Raj (Admin)';

export const getAuthHeaders = (): Record<string, string> => {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (currentToken) {
    headers['Authorization'] = `Bearer ${currentToken}`;
  }
  return headers;
};

async function requestRoleToken(role: UserRole, username?: string) {
  const uname = username || (role === 'admin' ? 'Raj' : role === 'red_lead' ? 'RedLead' : role === 'blue_lead' ? 'BlueLead' : 'Somesh');
  const query = new URLSearchParams({ role, username: uname });
  const res = await fetch(`${API_BASE}/auth/demo-token?${query}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  });
  if (!res.ok) throw new Error('Failed to refresh demo token');
  const data = await res.json();
  currentToken = data.access_token;
  currentRole = data.role as UserRole;
  currentUsername = data.username;
  localStorage.setItem('bayora_token', currentToken);
  localStorage.setItem('bayora_role', currentRole);
  localStorage.setItem('bayora_username', currentUsername);
  return data;
}

async function apiFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const send = () => fetch(url, { ...init, headers: getAuthHeaders() });
  const res = await send();
  if (res.status !== 401) return res;
  try {
    await requestRoleToken(currentRole);
  } catch {
    return res;
  }
  return send();
}

export const api = {
  // Auth & Roles
  async switchRole(role: UserRole, username?: string): Promise<{ access_token: string; role: string; username: string }> {
    return requestRoleToken(role, username);
  },

  getCurrentRole(): UserRole {
    return currentRole;
  },

  getCurrentUsername(): string {
    return currentUsername;
  },

  // Telemetry
  async getTelemetry(): Promise<SystemTelemetry> {
    const res = await apiFetch(`${API_BASE}/telemetry/system`);
    if (!res.ok) throw new Error('Failed to fetch telemetry');
    return res.json();
  },

  async getSideChannelStats(): Promise<any> {
    const res = await apiFetch(`${API_BASE}/telemetry/side-channel`);
    if (!res.ok) throw new Error('Failed to fetch side channel data');
    return res.json();
  },

  // Evaluations
  async getEvaluations(limit: number = 50): Promise<Evaluation[]> {
    const res = await apiFetch(`${API_BASE}/evaluations/?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch evaluations');
    return res.json();
  },

  async runEvaluation(payload: {
    prompt: string;
    attack_type?: string;
    category?: string;
    severity?: string;
    bypass_blue_team?: boolean;
  }): Promise<Evaluation> {
    const res = await apiFetch(`${API_BASE}/evaluations/run`, {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Evaluation failed');
    }
    return res.json();
  },

  // Orchestrator Continuous Loop (Attack -> Detect -> Defend -> Retest)
  async runContinuousLoop(params: {
    attack_category?: string;
    technique?: string;
    custom_prompt?: string;
    mutate?: boolean;
  }): Promise<LoopResult> {
    const res = await apiFetch(`${API_BASE}/evaluations/continuous-loop`, {
      method: 'POST',
      body: JSON.stringify(params)
    });
    if (!res.ok) throw new Error('Continuous loop failed');
    return res.json();
  },

  // Red Team
  async getAttackScenarios(): Promise<AttackScenario[]> {
    const res = await apiFetch(`${API_BASE}/red-team/scenarios`);
    if (!res.ok) throw new Error('Failed to fetch attack scenarios');
    return res.json();
  },

  async generateAttackPayload(params: { category: string; technique: string; mutate: boolean }): Promise<any> {
    const res = await apiFetch(`${API_BASE}/red-team/generate?category=${params.category}&technique=${params.technique}&mutate=${params.mutate}`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to generate attack payload');
    return res.json();
  },

  // Blue Team
  async getDefenseRules(): Promise<DefenseRule[]> {
    const res = await apiFetch(`${API_BASE}/blue-team/rules`);
    if (!res.ok) throw new Error('Failed to fetch defense rules');
    return res.json();
  },

  async createDefenseRule(rule: { name: string; description?: string; category: string; pattern: string; action: string }): Promise<DefenseRule> {
    const res = await apiFetch(`${API_BASE}/blue-team/rules`, {
      method: 'POST',
      body: JSON.stringify(rule)
    });
    if (!res.ok) throw new Error('Failed to create defense rule');
    return res.json();
  },

  async toggleDefenseRule(ruleId: number): Promise<DefenseRule> {
    const res = await apiFetch(`${API_BASE}/blue-team/rules/${ruleId}/toggle`, {
      method: 'PATCH'
    });
    if (!res.ok) throw new Error('Failed to toggle defense rule');
    return res.json();
  },

  async testInputGuardrail(prompt: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/blue-team/test-input?prompt=${encodeURIComponent(prompt)}`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to test input guardrail');
    return res.json();
  },

  // Audit Chain & Cryptographic Verification
  async getAuditBlocks(): Promise<AuditBlock[]> {
    const res = await apiFetch(`${API_BASE}/audit/blocks`);
    if (!res.ok) throw new Error('Failed to fetch audit blocks');
    return res.json();
  },

  async verifyAuditChain(): Promise<AuditVerificationResult> {
    const res = await apiFetch(`${API_BASE}/audit/verify`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Verification request failed');
    return res.json();
  },

  async simulateTamper(blockIndex: number, tamperedPayload: string): Promise<any> {
    const res = await apiFetch(`${API_BASE}/audit/tamper-simulate`, {
      method: 'POST',
      body: JSON.stringify({ block_index: blockIndex, tampered_payload: tamperedPayload })
    });
    if (!res.ok) throw new Error('Failed to simulate tamper');
    return res.json();
  },

  async restoreAuditChain(): Promise<any> {
    const res = await apiFetch(`${API_BASE}/audit/restore`, {
      method: 'POST'
    });
    if (!res.ok) throw new Error('Failed to restore chain');
    return res.json();
  },

  // Policies & OPA
  async getPolicies(): Promise<SecurityPolicy[]> {
    const res = await apiFetch(`${API_BASE}/policies/`);
    if (!res.ok) throw new Error('Failed to fetch policies');
    return res.json();
  },

  async evaluatePolicy(source: string, target: string, action: string, mediated: boolean = false): Promise<any> {
    const res = await apiFetch(`${API_BASE}/policies/evaluate`, {
      method: 'POST',
      body: JSON.stringify({
        source,
        target,
        action,
        prompt_length: 250,
        mediated_by_controller: mediated
      })
    });
    if (!res.ok) throw new Error('Policy evaluation failed');
    return res.json();
  }
};
