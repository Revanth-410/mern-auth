import React, { useContext } from "react";
import { assets } from "../assets/assets";
import { AppContext } from "../context/AppContext";

const Header = () => {
  const { userData } = useContext(AppContext);

  return (
    <div className="flex flex-col items-center mt-20 px-4 text-center text-gray-800 ">
      <img
        src={assets.header_img}
        alt=""
        className="w-36 h-36 rounded-full mb-6"
      />
      <h1 className="font-medium mb-2 flex items-center gap-2 text-xl sm:text-3xl">
        Hey {userData ? userData.name : "Developer!"}
        <img src={assets.hand_wave} alt="" className="w-8 aspect-square" />
      </h1>
      <h2 className="text-3xl sm:text-5xl font-semibold mb-4">
        Welcome to Our App.
      </h2>
      <p className="mb-5 max-w-md ">
        Let's start with a quick product tour amd we will have you up and
        running in no time.
      </p>
      <button className="cursor-pointer border border-gray-500 rounded-full px-8 py-2.5 hover:bg-gray-500 transition-all">
        Get Started
      </button>
    </div>
  );
};

export default Header;
