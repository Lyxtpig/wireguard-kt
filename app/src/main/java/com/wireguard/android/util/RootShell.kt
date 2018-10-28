/*
 * Copyright © 2017-2018 Harsh Shandilya <msfjarvis@gmail.com>. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.util

import android.content.Context
import com.topjohnwu.superuser.Shell
import com.wireguard.android.Application.Companion.localBinaryDir
import com.wireguard.android.Application.Companion.localTemporaryDir
import com.wireguard.android.R
import timber.log.Timber
import java.io.FileNotFoundException
import java.io.IOException

open class RootShell(private var context: Context) {
    private val deviceNotRootedMessage by lazy { context.getString(R.string.error_root) }

    init {
        Timber.tag(TAG)
    }

    private fun isRootAvailable(): Boolean {
        return Shell.rootAccess()
    }

    fun start() {
        Timber.tag("TEST_REE")
        if (!isRootAvailable())
            throw IOException(deviceNotRootedMessage)
        if (!localBinaryDir.isDirectory && !localBinaryDir.mkdirs())
            throw FileNotFoundException("Could not create local binary directory")
        if (!localTemporaryDir.isDirectory && !localTemporaryDir.mkdirs())
            throw FileNotFoundException("Could not create local temporary directory")
    }

    @Throws(IOException::class, NoRootException::class)
    fun run(command: String, output: ArrayList<String>? = null): Int {
        var returnCode = 0
        if (!isRootAvailable())
            throw NoRootException(deviceNotRootedMessage)
        Shell.su(command).submit { result ->
            output?.addAll(result.out.plus(result.err))
            Timber.d("executing: %s", command)
            Timber.d("stdout: %s", result.out)
            Timber.d("stderr: %s", result.err)
            Timber.d("exit: %s", result.code)
            returnCode = result.code
        }
        return returnCode
    }

    class NoRootException internal constructor(message: String) : Exception(message)

    companion object {
        private val TAG = "WireGuard/" + RootShell::class.java.simpleName
    }
}