import React, { useState, useEffect } from "react";
import { CircularProgress, Card, CardBody, CardFooter, Chip } from "@nextui-org/react";

export default function App() {
  const [ramUsage, setRamUsage] = useState(0);
  const [dataPointsValue2, setDataPointsValue2] = useState(0);

  useEffect(() => {
    const fetchData = () => {
      // Fetch data from the API
      fetch('https://server.govindsr.me/server-info')
        .then(response => response.json())
        .then(data => {
          // Update state based on the actual structure of the API response
          setRamUsage(100 - (data.memory.free / data.memory.total) * 100);
          setDataPointsValue2(data.serverTime);
        })
        .catch(error => console.error('Error fetching data:', error));
    };

    // Fetch data initially
    fetchData();

    // Set up an interval to fetch data every 1 second
    const intervalId = setInterval(fetchData, 1000);

    // Clear the interval when the component is unmounted
    return () => clearInterval(intervalId);
  }, []);

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold underline">    </h1>
      <div className="flex flex-wrap gap-4">
        {/* Self Hosted Server Card */}
        <Card className="w-full md:w-[250px] h-[250px] md:h-[250px] border-none bg-gradient-to-br from-violet-500 to-fuchsia-500">
         <CardBody className="justify-center items-center pb-0">
          <h2 className="text-l font-bold mb-2">About the Self Hosted Server</h2>
          <p>A project by Govind S R</p>
          <p><a href="https://theinfinox.in" target="_blank" rel="noopener noreferrer">theinfinox.in (Portfolio)</a></p>
          <p>Hostname: pi</p>
          <p>Platform: linux</p>
          <p>Architecture: arm64</p>
          <p>Release: 5.4.0-1097-raspi</p>
          <br></br>
          <Chip
            classNames={{
              base: "border-1 border-white/30",
              content: "text-white/90 text-small font-semibold",
            }}
            variant="bordered">
            {`${dataPointsValue2}`}
          </Chip>
        </CardBody>
      </Card>      

{/* Card 1 */}
      <Card className="w-full md:w-[250px] h-[250px] md:h-[250px] border-none bg-gradient-to-br from-violet-500 to-fuchsia-500">
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
        <CardFooter className="justify-center items-center pt-0">
          <Chip
            classNames={{
              base: "border-1 border-white/30",
              content: "text-white/90 text-small font-semibold",
            }}
            variant="bordered"
          >
            {`RAM Usage ${ramUsage.toFixed(2)} %`}
          </Chip>
        </CardFooter>
      </Card>

     
    </div></div>
  );
}
