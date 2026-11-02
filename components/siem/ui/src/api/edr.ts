/**
 * EDR API Client
 */

import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: `${API_BASE_URL}/api/v1/edr`,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const edrApi = {
  // Statistics
  getStatistics: async () => {
    const response = await api.get('/statistics');
    return response.data;
  },

  // Agents
  getAgents: async (params?: any) => {
    const response = await api.get('/agents', { params });
    return response.data;
  },

  getAgent: async (agentId: string) => {
    const response = await api.get(`/agents/${agentId}`);
    return response.data;
  },

  // Events
  getEvents: async (params?: any) => {
    const response = await api.get('/events', { params });
    return response.data;
  },

  // Threats
  getThreats: async (params?: any) => {
    const response = await api.get('/threats', { params });
    return response.data;
  },

  getThreat: async (threatId: number) => {
    const response = await api.get(`/threats/${threatId}`);
    return response.data;
  },

  respondToThreat: async (threatId: number, action: string) => {
    const response = await api.post(`/threats/${threatId}/respond`, { action });
    return response.data;
  },

  // Processes
  getProcesses: async (agentId: string) => {
    const response = await api.get('/processes', { params: { agent_id: agentId } });
    return response.data;
  },

  // Network
  getNetworkConnections: async (agentId: string) => {
    const response = await api.get('/network-connections', { params: { agent_id: agentId } });
    return response.data;
  },

  // File operations
  getFileOperations: async (agentId: string, operationType?: string) => {
    const response = await api.get('/file-operations', { 
      params: { agent_id: agentId, operation_type: operationType } 
    });
    return response.data;
  },
};
