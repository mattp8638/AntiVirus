import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Activity, Shield, AlertTriangle, Server, TrendingUp } from 'lucide-react';
import { edrApi } from '@/api/edr';

interface EDRStats {
  total_agents: number;
  online_agents: number;
  offline_agents: number;
  total_threats: number;
  critical_threats: number;
  events_24h: number;
}

const EDRDashboard: React.FC = () => {
  const [stats, setStats] = useState<EDRStats | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 10000); // Refresh every 10s
    return () => clearInterval(interval);
  }, []);

  const loadStats = async () => {
    try {
      const data = await edrApi.getStatistics();
      setStats(data);
    } catch (error) {
      console.error('Failed to load EDR stats:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-screen">Loading...</div>;
  }

  const uptime = stats ? ((stats.online_agents / stats.total_agents) * 100).toFixed(1) : 0;

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">EDR/XDR Dashboard</h1>
        <Badge variant={stats?.critical_threats ? 'destructive' : 'default'}>
          {stats?.critical_threats || 0} Critical Threats
        </Badge>
      </div>

      {stats && stats.critical_threats > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            {stats.critical_threats} critical threat(s) detected requiring immediate attention!
          </AlertDescription>
        </Alert>
      )}

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Endpoints</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.total_agents || 0}</div>
            <p className="text-xs text-muted-foreground">
              {stats?.online_agents || 0} online, {stats?.offline_agents || 0} offline
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Endpoint Health</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{uptime}%</div>
            <p className="text-xs text-muted-foreground">Uptime in last 24h</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threats Detected</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.total_threats || 0}</div>
            <p className="text-xs text-red-600">
              {stats?.critical_threats || 0} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Events (24h)</CardTitle>
            <TrendingUp className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">
              {stats?.events_24h?.toLocaleString() || 0}
            </div>
            <p className="text-xs text-muted-foreground">Telemetry events</p>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="cursor-pointer hover:bg-accent" onClick={() => window.location.href = '/edr/agents'}>
          <CardHeader>
            <CardTitle className="text-lg">View Endpoints</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Monitor and manage all protected endpoints
            </p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:bg-accent" onClick={() => window.location.href = '/edr/threats'}>
          <CardHeader>
            <CardTitle className="text-lg">Active Threats</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              View and respond to detected threats
            </p>
          </CardContent>
        </Card>

        <Card className="cursor-pointer hover:bg-accent" onClick={() => window.location.href = '/edr/events'}>
          <CardHeader>
            <CardTitle className="text-lg">Event Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              Browse real-time telemetry and events
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default EDRDashboard;
