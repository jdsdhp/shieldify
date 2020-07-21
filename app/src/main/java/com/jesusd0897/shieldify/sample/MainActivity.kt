/*
 * Copyright (c) 2020 jesusd0897.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.jesusd0897.shieldify.sample

import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import com.jesusd0897.shieldify.Shieldify

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

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
    }
}