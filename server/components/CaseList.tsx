"use client";

import { Case } from "@prisma/client";

interface Props {
  cases: Case[];
}

export function CaseList({ cases }: Props) {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800 border-red-200";
      case "high":
        return "bg-orange-100 text-orange-800 border-orange-200";
      case "medium":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "low":
        return "bg-blue-100 text-blue-800 border-blue-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "open":
        return "bg-red-100 text-red-800 border-red-200";
      case "investigating":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "resolved":
        return "bg-green-100 text-green-800 border-green-200";
      case "false_positive":
        return "bg-gray-100 text-gray-800 border-gray-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  return (
    <div className="space-y-3">
      {cases.map((case_) => (
        <div
          key={case_.id}
          className="border border-gray-200 rounded-lg p-4 bg-white hover:shadow-md transition-shadow cursor-pointer"
        >
          <div className="flex justify-between items-start">
            <div className="flex-1">
              <h3 className="font-semibold text-gray-900">{case_.title}</h3>
              {case_.description && (
                <p className="mt-1 text-sm text-gray-600 line-clamp-2">
                  {case_.description}
                </p>
              )}
            </div>
            <div className="flex gap-2 ml-4 flex-shrink-0">
              <span
                className={`px-2 py-1 rounded text-xs font-medium border ${getSeverityColor(
                  case_.severity
                )}`}
              >
                {case_.severity}
              </span>
              <span
                className={`px-2 py-1 rounded text-xs font-medium border ${getStatusColor(
                  case_.status
                )}`}
              >
                {case_.status}
              </span>
            </div>
          </div>
          <div className="mt-3 flex items-center gap-4 text-xs text-gray-500">
            <span>Created {new Date(case_.createdAt).toLocaleString()}</span>
            <span>Updated {new Date(case_.updatedAt).toLocaleString()}</span>
          </div>
        </div>
      ))}
    </div>
  );
}
