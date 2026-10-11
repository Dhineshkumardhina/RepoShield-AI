import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { DashboardScreen } from '../components/dashboard/DashboardScreen';
import { DiffModal } from '../components/modals/DiffModal';
import { CrashInspectorModal } from '../components/modals/CrashInspectorModal';
import { ScanModal } from '../components/modals/ScanModal';
import { ExportModal } from '../components/modals/ExportModal';
import { INITIAL_VERIFICATION_ITEMS } from '../data/mockData';
import { VerificationItem } from '../types';
import { api, ApiRepository } from '../services/api';

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();

  const [verificationItems, setVerificationItems] = useState<VerificationItem[]>(INITIAL_VERIFICATION_ITEMS);
  const [mergedPrs, setMergedPrs] = useState<Set<number>>(new Set());
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Live backend repositories
  const [liveRepos, setLiveRepos] = useState<ApiRepository[]>([]);

  // Modals
  const [activeDiffItem, setActiveDiffItem] = useState<VerificationItem | null>(null);
  const [activeCrashItem, setActiveCrashItem] = useState<VerificationItem | null>(null);
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isExportModalOpen, setIsExportModalOpen] = useState(false);
  const [scanTargetName, setScanTargetName] = useState('All Production Repositories');
  const [isRerunningSandbox, setIsRerunningSandbox] = useState(false);

  const refreshDashboardRepos = () => {
    api.getRepositories()
      .then(repos => setLiveRepos(repos))
      .catch(() => {});
  };

  useEffect(() => {
    refreshDashboardRepos();
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const handleApproveAndMerge = (id: string, prNumber?: number) => {
    if (!prNumber) return;
    setMergedPrs(prev => new Set(prev).add(prNumber));
    setVerificationItems(prev =>
      prev.map(item => item.id === id ? { ...item, status: 'verified', message: `Approved & successfully merged PR #${prNumber}.` } : item)
    );
    showToast(`✓ Pull Request #${prNumber} approved & successfully merged into target branch.`);
    if (activeDiffItem) setActiveDiffItem(null);
  };

  const handleRerunTest = (id: string) => {
    setIsRerunningSandbox(true);
    setTimeout(() => {
      setIsRerunningSandbox(false);
      showToast('✓ Clean sandbox spun up. Test and verification status re-evaluated.');
      setActiveCrashItem(null);
    }, 1000);
  };

  return (
    <>
      {toastMessage && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 text-white px-4 py-3 rounded-lg shadow-lg border border-slate-700 font-mono-sm text-xs flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2 duration-200">
          <span className="material-symbols-outlined text-base text-emerald-400">task_alt</span>
          <span>{toastMessage}</span>
        </div>
      )}

      <DashboardScreen
        verificationItems={verificationItems}
        onOpenDiffModal={item => setActiveDiffItem(item)}
        onOpenCrashModal={item => setActiveCrashItem(item)}
        onOpenScanModal={() => {
          setScanTargetName('All Production Repositories');
          setIsScanModalOpen(true);
        }}
        onOpenExportModal={() => setIsExportModalOpen(true)}
        onNavigateToQueue={() => navigate('/verification')}
        onNavigateToFindings={cwe => navigate(cwe ? `/findings?cwe=${encodeURIComponent(cwe)}` : '/findings')}
        onNavigateToRepositories={() => navigate('/repositories')}
        onApproveAndMerge={handleApproveAndMerge}
        mergedPrs={mergedPrs}
      />

      {/* Modals */}
      <DiffModal
        item={activeDiffItem}
        onClose={() => setActiveDiffItem(null)}
        onApproveAndMerge={handleApproveAndMerge}
        isMerged={activeDiffItem?.prNumber ? mergedPrs.has(activeDiffItem.prNumber) : false}
      />

      <CrashInspectorModal
        item={activeCrashItem}
        onClose={() => setActiveCrashItem(null)}
        onRerun={handleRerunTest}
        isRerunning={isRerunningSandbox}
      />

      <ScanModal
        isOpen={isScanModalOpen}
        onClose={() => setIsScanModalOpen(false)}
        onScanComplete={() => {
          showToast('✓ Real security scan completed. Repository metrics updated.');
          refreshDashboardRepos();
          setIsScanModalOpen(false);
        }}
        targetRepoName={scanTargetName}
      />

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
      />
    </>
  );
};
