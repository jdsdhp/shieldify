🛡 Shieldify
=======

Store and recover sensible data into Android Key Store easily.

[![JitPack](https://jitpack.io/v/jdsdhp/shieldify.svg)](https://jitpack.io/#jdsdhp/shieldify) 
[![API](https://img.shields.io/badge/API-18%2B-red.svg?style=flat)](https://android-arsenal.com/api?level=18) 
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Twitter](https://img.shields.io/badge/Twitter-@jdsdhp-9C27B0.svg)](https://twitter.com/jdsdhp)

## Including in your project

#### Gradle

```gradle
allprojects  {
    repositories {
        ...
        maven { url 'https://jitpack.io' }
    }
}
dependencies {
    implementation 'com.github.jdsdhp:shieldify:$version'
}
```

## Usage

### Kotlin
Should be used a specific alias for Android Key Store. In this example app was used  "MY_APP_ALIAS".

```kotlin
val value1 = "A secret value"
val value2 = "Other secret value"

val shieldify = Shieldify(
    context = this,
    keyStoreAlias = "MY_APP_ALIAS"
)

val key1: String = shieldify.encryptData(value1)
val key2: String = shieldify.encryptData(value2)

val decryptedValue1: String = shieldify.decryptData(key1)
val decryptedValue2: String = shieldify.decryptData(key2)

Log.d("TAG", "decryptedValue 1 = $decryptedValue1") // Show "decryptedValue 1 = A secret value"
Log.d("TAG", "decryptedValue 2 = $decryptedValue2") // Show "decryptedValue 2 = Other secret value"
```

## Sample project

It's very important to check out the sample app. Most techniques that you would want to implement are already implemented in the examples.

View the sample app's source code [here](https://github.com/jdsdhp/shieldify/tree/master/app)

License
=======

    Copyright (c) 2020 jesusd0897.
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
