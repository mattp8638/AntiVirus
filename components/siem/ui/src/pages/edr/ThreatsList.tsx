import React, { useState, useEffect } from 'react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { AlertTriangle, Shield, CheckCircle } from 'lucide-react';
import { edrApi } from '@/api/edr';

interface Threat {
  id: number;
  agent_id: string;
  threat_type: string;
  threat_name: string;
  severity: string;
  status: string;
  process_name: string;
  file_path: string;
  file_hash: string;
  mitre_tactics: string[];
  ml_score: number;
  timestamp: string;
}

const ThreatsList: React.FC = () => {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  useEffect(() => {
    loadThreats();
    const interval = setInterval(loadThreats, 15000); // Refresh every 15s
    return () => clearInterval(interval);
  }, [severityFilter, statusFilter]);

  const loadThreats = async () => {
    try {
      const params: any = {};
      if (severityFilter !== 'all') params.severity = severityFilter;
      if (statusFilter !== 'all') params.status = statusFilter;
      
      const data = await edrApi.getThreats(params);
      setThreats(data);
    } catch (error) {
      console.error('Failed to load threats:', error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'secondary';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      case 'medium':
        return <Shield className="h-4 w-4 text-yellow-500" />;
      default:
        return <CheckCircle className="h-4 w-4 text-blue-500" />;
    }
  };

  const handleRespond = async (threatId: number, action: string) => {
    try {
      await edrApi.respondToThreat(threatId, action);
      loadThreats();
    } catch (error) {
      console.error('Failed to respond to threat:', error);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Threat Detections</h1>
        <div className="flex space-x-2">
          <Select value={severityFilter} onValueChange={setSeverityFilter}>
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
            </SelectContent>
          </Select>

          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-32">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="detected">Detected</SelectItem>
              <SelectItem value="investigating">Investigating</SelectItem>
              <SelectItem value="contained">Contained</SelectItem>
              <SelectItem value="resolved">Resolved</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12"></TableHead>
              <TableHead>Threat Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Process</TableHead>
              <TableHead>ML Score</TableHead>
              <TableHead>Detected</TableHead>
              <TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center">Loading...</TableCell>
              </TableRow>
            ) : threats.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center">No threats found</TableCell>
              </TableRow>
            ) : (
              threats.map((threat) => (
                <TableRow key={threat.id} className={threat.severity === 'critical' ? 'bg-red-50' : ''}>
                  <TableCell>{getSeverityIcon(threat.severity)}</TableCell>
                  <TableCell className="font-medium">{threat.threat_name}</TableCell>
                  <TableCell>{threat.threat_type}</TableCell>
                  <TableCell>
                    <Badge variant={getSeverityColor(threat.severity)}>
                      {threat.severity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline">{threat.status}</Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{threat.process_name}</TableCell>
                  <TableCell>
                    <span className={threat.ml_score >= 80 ? 'text-red-600 font-bold' : ''}>
                      {threat.ml_score?.toFixed(1)}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs">
                    {new Date(threat.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    {threat.status === 'detected' && (
                      <div className="flex space-x-1">
                        <Button 
                          variant="destructive" 
                          size="sm"
                          onClick={() => handleRespond(threat.id, 'isolate')}
                        >
                          Isolate
                        </Button>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => window.location.href = `/edr/threats/${threat.id}`}
                        >
                          Details
                        </Button>
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="text-sm text-muted-foreground">
        Showing {threats.length} threat(s)
      </div>
    </div>
  );
};

export default ThreatsList;
