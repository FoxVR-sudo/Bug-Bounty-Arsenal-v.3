import React, { useEffect, useMemo, useState, useRef } from 'react';
import { FiUsers, FiUserPlus, FiTrash2, FiMail, FiCopy, FiCheck, FiShield, FiEye } from 'react-icons/fi';
import DashboardLayout from '../components/DashboardLayout';
import LoadingState from '../components/states/LoadingState';
import ErrorState from '../components/states/ErrorState';
import EmptyState from '../components/states/EmptyState';
import FieldError from '../components/forms/FieldError';
import { isEmail, isNonEmpty } from '../lib/validation';
import api from '../services/api';
import useModalA11y from '../hooks/useModalA11y';

const TeamManagement = () => {
  const [team, setTeam] = useState(null);
  const [members, setMembers] = useState([]);
  const [invitations, setInvitations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Create team form
  const [showCreateTeam, setShowCreateTeam] = useState(false);
  const [teamName, setTeamName] = useState('');
  const [teamNameTouched, setTeamNameTouched] = useState(false);
  const [creatingTeam, setCreatingTeam] = useState(false);
  
  // Invite member form
  const [showInvite, setShowInvite] = useState(false);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  const [inviteEmailTouched, setInviteEmailTouched] = useState(false);
  const [invitingMember, setInvitingMember] = useState(false);
  
  // Copied invite code state
  const [copiedCode, setCopiedCode] = useState(false);

  const createTeamModalRef = useModalA11y(showCreateTeam, {
    onClose: () => setShowCreateTeam(false),
  });
  const inviteModalRef = useModalA11y(showInvite, {
    onClose: () => setShowInvite(false),
  });

  const createTeamTitleIdRef = useRef(`create-team-title-${Math.random().toString(36).slice(2)}`);
  const createTeamDescIdRef = useRef(`create-team-desc-${Math.random().toString(36).slice(2)}`);
  const inviteTitleIdRef = useRef(`invite-team-title-${Math.random().toString(36).slice(2)}`);
  const inviteDescIdRef = useRef(`invite-team-desc-${Math.random().toString(36).slice(2)}`);

  const teamNameError = useMemo(() => {
    if (!showCreateTeam) return null;
    if (!isNonEmpty(teamName)) return 'Team name is required.';
    return null;
  }, [showCreateTeam, teamName]);

  const inviteEmailError = useMemo(() => {
    if (!showInvite) return null;
    if (!isEmail(inviteEmail)) return 'Enter a valid email address.';
    return null;
  }, [showInvite, inviteEmail]);

  useEffect(() => {
    fetchTeamData();
  }, []);

  const fetchTeamData = async () => {
    setLoading(true);
    try {
      // Fetch user's team
      const teamResponse = await api.get('/teams/');

      const teamResults = teamResponse.data?.results || teamResponse.data;
      if (Array.isArray(teamResults) && teamResults.length > 0) {
        const userTeam = teamResults[0];
        setTeam(userTeam);
        
        // Fetch team members
        const membersResponse = await api.get(`/teams/${userTeam.id}/members/`);
        setMembers(membersResponse.data);
        
        // Fetch pending invitations
        const invitationsResponse = await api.get(`/teams/${userTeam.id}/invitations/`);
        setInvitations(invitationsResponse.data);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load team data');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateTeam = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (teamNameError) {
      setTeamNameTouched(true);
      return;
    }
    
    try {
      setCreatingTeam(true);
      await api.post('/teams/', { name: teamName });
      
      setSuccess('Team created successfully!');
      setShowCreateTeam(false);
      setTeamName('');
      setTeamNameTouched(false);
      fetchTeamData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create team');
    } finally {
      setCreatingTeam(false);
    }
  };

  const handleInviteMember = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (inviteEmailError) {
      setInviteEmailTouched(true);
      return;
    }
    
    try {
      setInvitingMember(true);
      await api.post(`/teams/${team.id}/invite/`, { email: inviteEmail, role: inviteRole });
      
      setSuccess('Invitation sent successfully!');
      setShowInvite(false);
      setInviteEmail('');
      setInviteRole('member');
      setInviteEmailTouched(false);
      fetchTeamData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send invitation');
    } finally {
      setInvitingMember(false);
    }
  };

  const handleRemoveMember = async (memberId) => {
    if (!window.confirm('Are you sure you want to remove this member?')) return;
    
    try {
      setError('');
      setSuccess('');
      await api.delete(`/teams/${team.id}/members/${memberId}/`);
      
      setSuccess('Member removed successfully');
      fetchTeamData();
    } catch (err) {
      setError('Failed to remove member');
    }
  };

  const handleCopyInviteCode = () => {
    if (team?.invite_code) {
      navigator.clipboard.writeText(team.invite_code);
      setCopiedCode(true);
      setTimeout(() => setCopiedCode(false), 2000);
    }
  };

  const getRoleBadge = (role) => {
    const styles = {
      admin: 'bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-200 dark:border-red-800/40',
      member: 'bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-900/30 dark:text-blue-200 dark:border-blue-800/40',
      viewer: 'bg-gray-50 text-gray-700 border-gray-200 dark:bg-gray-800/40 dark:text-gray-200 dark:border-gray-700',
    };
    return styles[role] || styles.viewer;
  };

  const getRoleIcon = (role) => {
    if (role === 'admin') return <FiShield size={16} />;
    if (role === 'member') return <FiUsers size={16} />;
    return <FiEye size={16} />;
  };

  if (loading) {
    return (
      <DashboardLayout>
        <LoadingState title="Loading team" subtitle="Fetching your team and members…" />
      </DashboardLayout>
    );
  }

  if (error && !team) {
    return (
      <DashboardLayout>
        <ErrorState
          title="Couldn’t load team"
          message={error}
          action={
            <button
              onClick={() => {
                setError('');
                fetchTeamData();
              }}
              className="ui-btn ui-btn-primary"
            >
              Retry
            </button>
          }
        />
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8">
          <h1 className="ui-title mb-2">Team Management</h1>
          <p className="ui-subtitle">Collaborate with your team members on security scans</p>
        </div>

        {error && (
          <div className="ui-alert ui-alert-error mb-6">
            {error}
          </div>
        )}

        {success && (
          <div className="ui-alert ui-alert-success mb-6">
            {success}
          </div>
        )}

        {!team ? (
          <EmptyState
            title="No team yet"
            message="Create a team to collaborate on security scans."
            action={
              <button onClick={() => setShowCreateTeam(true)} className="ui-btn ui-btn-primary">
                Create team
              </button>
            }
          />
        ) : (
          <div className="space-y-6">
            {/* Team Info Card */}
            <div className="ui-card p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className="text-2xl font-bold text-gray-900 dark:text-white">{team.name}</h2>
                  <p className="text-gray-600 dark:text-gray-300 text-sm mt-1">
                    {members.length} / {team.max_members === -1 ? 'Unlimited' : (team.max_members || 10)} members
                  </p>
                </div>
                <button
                  onClick={() => setShowInvite(true)}
                  className="ui-btn ui-btn-primary flex items-center gap-2"
                >
                  <FiUserPlus /> Invite Member
                </button>
              </div>

              {/* Invite Code */}
              <div className="p-4 rounded-lg border bg-gray-50 dark:bg-gray-900/40 border-gray-200 dark:border-gray-700">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-sm font-semibold mb-1 text-gray-700 dark:text-gray-200">Team Invite Code</h4>
                    <p className="text-xs text-gray-500 dark:text-gray-400">Share this code with team members to join</p>
                  </div>
                  <div className="flex items-center gap-3">
                    <code className="px-4 py-2 rounded font-mono text-lg border bg-white dark:bg-gray-950/40 border-gray-300 dark:border-gray-700 text-gray-900 dark:text-gray-100">
                      {team.invite_code}
                    </code>
                    <button
                      onClick={handleCopyInviteCode}
                      className="p-2 rounded transition border bg-white dark:bg-gray-900 border-gray-300 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 text-gray-700 dark:text-gray-200"
                      title="Copy invite code"
                    >
                      {copiedCode ? <FiCheck className="text-green-600" /> : <FiCopy />}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            {/* Team Members */}
            <div className="ui-card">
              <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                <h3 className="text-xl font-bold text-gray-900 dark:text-white">Team Members</h3>
              </div>
              <div className="divide-y divide-gray-200 dark:divide-gray-700">
                {members.map((member) => (
                  <div key={member.id} className="p-6 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-800/40">
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 bg-primary bg-opacity-10 rounded-full flex items-center justify-center">
                        <span className="text-primary font-bold">
                          {(member.user_email || '').charAt(0).toUpperCase()}
                        </span>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900 dark:text-white">{member.user_email}</h4>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs px-2 py-1 rounded border font-semibold flex items-center gap-1 ${getRoleBadge(member.role)}`}>
                            {getRoleIcon(member.role)}
                            {member.role.toUpperCase()}
                          </span>
                          {member.can_create_scans && (
                            <span className="text-xs text-gray-500 dark:text-gray-400">• Can create scans</span>
                          )}
                          {member.can_manage_members && (
                            <span className="text-xs text-gray-500 dark:text-gray-400">• Can manage members</span>
                          )}
                        </div>
                      </div>
                    </div>
                    {member.user !== team.owner && (
                      <button
                        onClick={() => handleRemoveMember(member.id)}
                        className="p-2 text-red-600 dark:text-red-400 rounded transition hover:bg-red-50 dark:hover:bg-red-900/30"
                        title="Remove member"
                      >
                        <FiTrash2 />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Pending Invitations */}
            {invitations.length > 0 && (
              <div className="ui-card">
                <div className="p-6 border-b border-gray-200 dark:border-gray-700">
                  <h3 className="text-xl font-bold text-gray-900 dark:text-white">Pending Invitations</h3>
                </div>
                <div className="divide-y divide-gray-200 dark:divide-gray-700">
                  {invitations.map((invitation) => (
                    <div key={invitation.id} className="p-6 flex items-center justify-between">
                      <div className="flex items-center gap-4">
                        <FiMail className="text-gray-400 dark:text-gray-500" size={20} />
                        <div>
                          <h4 className="font-semibold text-gray-900 dark:text-white">{invitation.email}</h4>
                          <p className="text-xs mt-1 text-gray-500 dark:text-gray-400">
                            Invited {new Date(invitation.created_at).toLocaleDateString()} • Expires {new Date(invitation.expires_at).toLocaleDateString()}
                          </p>
                        </div>
                      </div>
                      <span className={`text-xs px-3 py-1 rounded border font-semibold ${getRoleBadge(invitation.role)}`}>
                        {invitation.role.toUpperCase()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Create Team Modal */}
        {showCreateTeam && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setShowCreateTeam(false);
            }}
          >
            <div
              ref={createTeamModalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby={createTeamTitleIdRef.current}
              aria-describedby={createTeamDescIdRef.current}
              tabIndex={-1}
              className="ui-card p-8 max-w-md w-full bg-white/95 dark:bg-gray-900/80 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/50"
            >
              <h3
                id={createTeamTitleIdRef.current}
                className="text-2xl font-bold mb-2 text-gray-900 dark:text-white"
              >
                Create Team
              </h3>
              <p id={createTeamDescIdRef.current} className="text-sm text-gray-600 dark:text-gray-300 mb-6">
                Create a team to collaborate on scans.
              </p>
              <form onSubmit={handleCreateTeam} noValidate>
                <div className="mb-6">
                  <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">Team Name</label>
                  <input
                    type="text"
                    value={teamName}
                    onChange={(e) => {
                      setTeamName(e.target.value);
                      if (!teamNameTouched) setTeamNameTouched(true);
                    }}
                    onBlur={() => setTeamNameTouched(true)}
                    placeholder="My Security Team"
                    className={`ui-input ${teamNameTouched && teamNameError ? 'ui-input-error' : ''}`}
                    aria-invalid={teamNameTouched && !!teamNameError}
                    aria-describedby="team-name-error"
                  />
                  <div id="team-name-error">
                    <FieldError message={teamNameTouched ? teamNameError : null} />
                  </div>
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    disabled={creatingTeam || !!teamNameError}
                    className="ui-btn ui-btn-primary flex-1 justify-center"
                  >
                    {creatingTeam ? 'Creating…' : 'Create Team'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowCreateTeam(false);
                      setTeamNameTouched(false);
                    }}
                    disabled={creatingTeam}
                    className="ui-btn ui-btn-secondary flex-1 justify-center"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Invite Member Modal */}
        {showInvite && (
          <div
            className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
            onMouseDown={(e) => {
              if (e.target === e.currentTarget) setShowInvite(false);
            }}
          >
            <div
              ref={inviteModalRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby={inviteTitleIdRef.current}
              aria-describedby={inviteDescIdRef.current}
              tabIndex={-1}
              className="ui-card p-8 max-w-md w-full bg-white/95 dark:bg-gray-900/80 backdrop-blur-xl border border-gray-200/50 dark:border-gray-700/50"
            >
              <h3
                id={inviteTitleIdRef.current}
                className="text-2xl font-bold mb-2 text-gray-900 dark:text-white"
              >
                Invite Team Member
              </h3>
              <p id={inviteDescIdRef.current} className="text-sm text-gray-600 dark:text-gray-300 mb-6">
                Send an invitation email and choose a role.
              </p>
              <form onSubmit={handleInviteMember} noValidate>
                <div className="mb-4">
                  <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">Email Address</label>
                  <input
                    type="email"
                    value={inviteEmail}
                    onChange={(e) => {
                      setInviteEmail(e.target.value);
                      if (!inviteEmailTouched) setInviteEmailTouched(true);
                    }}
                    onBlur={() => setInviteEmailTouched(true)}
                    placeholder="colleague@example.com"
                    className={`ui-input ${inviteEmailTouched && inviteEmailError ? 'ui-input-error' : ''}`}
                    aria-invalid={inviteEmailTouched && !!inviteEmailError}
                    aria-describedby="invite-email-error"
                  />
                  <div id="invite-email-error">
                    <FieldError message={inviteEmailTouched ? inviteEmailError : null} />
                  </div>
                </div>
                <div className="mb-6">
                  <label className="block font-semibold mb-2 text-gray-700 dark:text-gray-200">Role</label>
                  <select
                    value={inviteRole}
                    onChange={(e) => setInviteRole(e.target.value)}
                    className="ui-select"
                  >
                    <option value="viewer">Viewer - Can only view scans</option>
                    <option value="member">Member - Can create and view scans</option>
                    <option value="admin">Admin - Full access</option>
                  </select>
                </div>
                <div className="flex gap-4">
                  <button
                    type="submit"
                    disabled={invitingMember || !!inviteEmailError}
                    className="ui-btn ui-btn-primary flex-1 justify-center"
                  >
                    {invitingMember ? 'Sending…' : 'Send Invitation'}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setShowInvite(false);
                      setInviteEmailTouched(false);
                    }}
                    disabled={invitingMember}
                    className="ui-btn ui-btn-secondary flex-1 justify-center"
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
};

export default TeamManagement;
