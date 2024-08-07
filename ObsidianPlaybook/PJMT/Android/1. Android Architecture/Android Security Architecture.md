- Every application on Android is run in a virtual machine known as Android Runtime
	- **Dalvin** was the original runtime, and is still referenced. 
		- Dalvin is not used in modern Android
	- **Android Runtime (ART)**
		- Modern translation layer from bytecode to device instructions
		- Every app runs in its own sandboxed virtual machine
			- Every single application in the Android phone runs in its own sandbox VM, and is assigned its own folder with its own owner
- Profiles
	- Used to separate App Data into various use cases
		- I.e. Work Profile, Personal Profile, etc. 
- Architecture Model
	- System Apps
	- Java API Framework
		- Lets you interact with other apps
			- Content Providers: a way of sharing data to other applications
	- Native C/C++ Libraries
	- Android Runtime
	- Hardware Abstraction Layer (HAL)
		- Allows applications to access hardware components irrespective of the device manufacturer or type
		- Allows apps to access camera, microphone, bluetooth, etc without needing specific drivers or manufacturer details
	- Linux Kernel