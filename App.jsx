import React, { useState, useEffect, useRef, useCallback } from "react";
import { CircularProgress, Card, CardBody, CardFooter, Chip } from "@nextui-org/react";

const POLL_INTERVAL_MS = 5000;
const API_URL = "https://server.govindsr.me/server-info";

export default function App() {
  const [ramUsage, setRamUsage] = useState(0);
  const [serverTime, setServerTime] = useState("--");
  const [isOnline, setIsOnline] = useState(true);
  const [lastUpdated, setLastUpdated] = useState("");
  const abortControllerRef = useRef(null);

  const fetchData = useCallback(() => {
    // Skip polling if document is hidden to save client & server resources
    if (document.visibilityState !== "visible") {
      return;
    }

    // Cancel any previous in-flight request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
    const controller = new AbortController();
    abortControllerRef.current = controller;

    fetch(API_URL, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`HTTP error ${response.status}`);
        }
        return response.json();
      })
      .then((data) => {
        if (data && typeof data === "object") {
          if (
            data.memory &&
            typeof data.memory.free === "number" &&
            typeof data.memory.total === "number" &&
            data.memory.total > 0
          ) {
            const usedPercentage = 100 - (data.memory.free / data.memory.total) * 100;
            setRamUsage(Math.min(100, Math.max(0, usedPercentage)));
          }
          if (data.serverTime) {
            setServerTime(String(data.serverTime));
          }
          setIsOnline(true);
          setLastUpdated(new Date().toLocaleTimeString());
        }
      })
      .catch((error) => {
        if (error.name !== "AbortError") {
          console.error("Telemetry fetch error:", error);
          setIsOnline(false);
        }
      });
  }, []);

  useEffect(() => {
    // Initial fetch
    fetchData();

    // Set up polling interval
    const intervalId = setInterval(fetchData, POLL_INTERVAL_MS);

    // Resume polling immediately when tab becomes visible
    const handleVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        fetchData();
      }
    };
    document.addEventListener("visibilitychange", handleVisibilityChange);

    return () => {
      clearInterval(intervalId);
      document.removeEventListener("visibilitychange", handleVisibilityChange);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [fetchData]);

  return (
    <div className="container mx-auto p-4">
      <div className="flex flex-wrap gap-4">
        {/* Self Hosted Server Card */}
        <Card className="w-full md:w-[260px] min-h-[250px] border-none bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white shadow-lg">
          <CardBody className="justify-center items-center text-center p-4">
            <h2 className="text-lg font-bold mb-1">Self-Hosted Server</h2>
            <p className="text-xs text-white/80 mb-2">A project by Govind S R</p>
            <p className="text-xs mb-3">
              <a
                href="https://theinfinox.in"
                target="_blank"
                rel="noopener noreferrer"
                className="underline hover:text-white/90 font-medium"
              >
                theinfinox.in (Portfolio)
              </a>
            </p>
            <div className="flex flex-col gap-1 text-xs text-white/90 mb-3">
              <p>Platform: Self-Hosted Linux</p>
              <p>
                Status:{" "}
                <span className={isOnline ? "text-emerald-200 font-semibold" : "text-rose-200 font-semibold"}>
                  {isOnline ? "Online" : "Connecting..."}
                </span>
              </p>
            </div>
            <Chip
              classNames={{
                base: "border-1 border-white/30 bg-white/10",
                content: "text-white/90 text-xs font-semibold",
              }}
              variant="bordered"
            >
              {`Server Time: ${serverTime}`}
            </Chip>
          </CardBody>
        </Card>

        {/* RAM Usage Card */}
        <Card className="w-full md:w-[260px] min-h-[250px] border-none bg-gradient-to-br from-violet-500 to-fuchsia-500 text-white shadow-lg">
          <CardBody className="justify-center items-center pb-0">
            <CircularProgress
              classNames={{
                svg: "w-36 h-36 drop-shadow-md",
                indicator: "stroke-white",
                track: "stroke-white/10",
                value: "text-3xl font-semibold text-white",
              }}
              value={ramUsage}
              strokeWidth={4}
              showValueLabel={true}
            />
          </CardBody>
          <CardFooter className="flex flex-col justify-center items-center pt-2 pb-4 gap-1">
            <Chip
              classNames={{
                base: "border-1 border-white/30 bg-white/10",
                content: "text-white/90 text-small font-semibold",
              }}
              variant="bordered"
            >
              {`RAM Usage: ${ramUsage.toFixed(2)} %`}
            </Chip>
            {lastUpdated && (
              <span className="text-[10px] text-white/70">
                Updated at {lastUpdated}
              </span>
            )}
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
