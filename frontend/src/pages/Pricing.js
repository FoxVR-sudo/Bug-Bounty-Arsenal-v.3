import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import DashboardLayout from '../components/DashboardLayout';
import { FiCheck, FiLoader } from 'react-icons/fi';
import api from '../services/api';

const Pricing = () => {
  const navigate = useNavigate();
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [currentPlan, setCurrentPlan] = useState(null);

  useEffect(() => {
    fetchPlans();
    fetchCurrentSubscription();
  }, []);

  const fetchPlans = async () => {
    try {
      const response = await api.get('/plans/');
      setPlans(response.data);
    } catch (err) {
      console.error('Failed to fetch plans:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchCurrentSubscription = async () => {
    try {
      const response = await api.get('/subscriptions/current/');
      setCurrentPlan(response.data.plan?.name || 'free');
    } catch (err) {
      console.error('Failed to fetch subscription:', err);
      setCurrentPlan('free');
    }
  };

  if (loading) {
    return (
      <DashboardLayout>
        <div className="p-8 flex items-center justify-center">
          <FiLoader className="animate-spin text-primary" size={48} />
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="ui-page">
        <div className="mb-8 text-center">
          <h1 className="ui-title">Pricing Plans</h1>
          <p className="ui-subtitle mt-2">Unlock powerful security scanning features</p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-6xl mx-auto">
          {plans.map((plan) => {
            const isCurrentPlan = plan.name === currentPlan;
            const isFree = plan.price === 0;
            const isPopular = plan.is_popular;
            
            return (
              <div
                key={plan.id}
                className={
                  isPopular
                    ? 'rounded-lg p-8 shadow-lg bg-primary text-white border-4 border-yellow-400 transform md:scale-105'
                    : 'ui-card p-8'
                }
              >
                {isPopular && (
                  <div className="text-center mb-2">
                    <span className="bg-yellow-400 text-yellow-900 px-3 py-1 rounded-full text-sm font-bold">
                      RECOMMENDED
                    </span>
                  </div>
                )}
                
                <div className="text-center mb-6">
                  <h3 className={`text-2xl font-bold mb-2 ${isPopular ? 'text-white' : 'text-gray-900 dark:text-white'}`}>{plan.display_name}</h3>
                  <div className="text-4xl font-bold mb-2">
                    {isFree ? 'Free' : `$${plan.price}`}
                  </div>
                  <div className={isPopular ? 'text-gray-200' : 'text-gray-600 dark:text-gray-300'}>
                    {isFree ? 'forever' : 'per month'}
                  </div>
                </div>
                
                <ul className={`space-y-3 mb-8 ${isPopular ? 'text-white' : 'text-gray-700 dark:text-gray-200'}`}>
                  <li className="flex items-start gap-2">
                    <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                    <span>{plan.daily_scan_limit === -1 ? 'Unlimited' : plan.daily_scan_limit} scans per day</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                    <span>{plan.monthly_scan_limit === -1 ? 'Unlimited' : plan.monthly_scan_limit} scans per month</span>
                  </li>
                  
                  {plan.features && plan.features.length > 0 ? (
                    plan.features.map((feature, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                        <span>{feature}</span>
                      </li>
                    ))
                  ) : (
                    <>
                      {plan.allow_teams && (
                        <li className="flex items-start gap-2">
                          <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                          <span>Team collaboration ({plan.max_team_members} members)</span>
                        </li>
                      )}
                      {plan.allow_integrations && (
                        <li className="flex items-start gap-2">
                          <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                          <span>Integrations ({plan.max_integrations} max)</span>
                        </li>
                      )}
                      {plan.allow_dangerous_tools && (
                        <li className="flex items-start gap-2">
                          <FiCheck className={`mt-1 flex-shrink-0 ${isPopular ? '' : 'text-green-500'}`} />
                          <span>Dangerous tools & custom payloads</span>
                        </li>
                      )}
                    </>
                  )}
                </ul>

                <button
                  onClick={() => {
                    if (isCurrentPlan) {
                      navigate('/subscription');
                    } else if (isFree) {
                      navigate('/dashboard');
                    } else if (plan.name === 'enterprise') {
                      navigate('/register-enterprise');
                    } else {
                      navigate('/subscription?upgrade=true');
                    }
                  }}
                  className={
                    isCurrentPlan
                      ? 'ui-btn ui-btn-secondary w-full justify-center'
                      : isPopular
                      ? 'ui-btn w-full justify-center bg-white text-primary hover:bg-gray-100'
                      : plan.name === 'enterprise'
                      ? 'ui-btn w-full justify-center bg-gray-900 text-white hover:bg-gray-800 dark:bg-gray-800 dark:hover:bg-gray-700'
                      : 'ui-btn ui-btn-primary w-full justify-center'
                  }
                >
                  {isCurrentPlan ? 'Current Plan' : isFree ? 'Get Started' : plan.name === 'enterprise' ? 'Contact Sales' : `Upgrade to ${plan.display_name}`}
                </button>
              </div>
            );
          })}
        </div>

        <div className="text-center mt-12">
          <button
            onClick={() => navigate('/dashboard')}
            className="mt-10 ui-btn ui-btn-ghost"
          >
            ← Back to Dashboard
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Pricing;
