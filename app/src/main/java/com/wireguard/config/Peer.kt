/*
 * Copyright © 2017-2018 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.config

import android.os.Parcel
import android.os.Parcelable
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.Application
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.crypto.KeyEncoding
import java9.lang.Iterables
import java.net.UnknownHostException
import java.util.ArrayList
import java.util.Arrays
import java.util.HashSet

/**
 * Represents the configuration for a WireGuard peer (a [Peer] block).
 */

class Peer {
    private val allowedIPsList: MutableList<InetNetwork>
    var endpoint: InetEndpoint? = null
        private set
    var persistentKeepalive: Int = 0
        private set
    var preSharedKey: String? = null
        private set(value) {
            var key = value
            if (key != null && key.isEmpty())
                key = null
            if (key != null)
                KeyEncoding.keyFromBase64(key)
            field = key
        }
    var publicKey: String? = null
        private set(value) {
            var key = value
            if (key != null && key.isEmpty())
                key = null
            if (key != null)
                KeyEncoding.keyFromBase64(key)
            field = key
        }
    private val context = Application.get()

    val allowedIPs: Array<InetNetwork>
        get() = allowedIPsList.toTypedArray()

    private var allowedIPsString: String?
        get() = if (allowedIPsList.isEmpty()) null else Attribute.iterableToString(allowedIPsList)
        set(allowedIPsString) {
            allowedIPsList.clear()
            addAllowedIPs(Attribute.stringToList(allowedIPsString))
        }

    private var endpointString: String?
        get() = endpoint?.endpoint
        set(value) {
            endpoint = if (value != null && !value.isEmpty())
                InetEndpoint(value)
            else
                null
        }

    private var persistentKeepaliveString: String?
        get() = if (persistentKeepalive == 0) null else Integer.valueOf(persistentKeepalive).toString()
        set(value) {
            persistentKeepalive = if (value != null && !value.isEmpty())
                Integer.parseInt(value, 10)
            else
                0
        }

    val resolvedEndpointString: String
        @Throws(UnknownHostException::class)
        get() {
            if (endpoint == null)
                throw UnknownHostException("{empty}")
            return endpoint!!.resolvedEndpoint
        }

    init {
        allowedIPsList = ArrayList()
    }

    private fun addAllowedIPs(allowedIPs: Array<String>?) {
        if (allowedIPs != null && allowedIPs.isNotEmpty()) {
            for (allowedIP in allowedIPs) {
                allowedIPsList.add(InetNetwork(allowedIP))
            }
        }
    }

    fun parse(line: String) {
        val key = Attribute.match(line) ?: throw IllegalArgumentException(
            context.getString(
                R.string.tunnel_error_interface_parse_failed,
                line
            )
        )
        when (key) {
            Attribute.ALLOWED_IPS -> addAllowedIPs(key.parseList(line))
            Attribute.ENDPOINT -> endpointString = key.parse(line)
            Attribute.PERSISTENT_KEEPALIVE -> persistentKeepaliveString = key.parse(line)
            Attribute.PRESHARED_KEY -> preSharedKey = key.parse(line)
            Attribute.PUBLIC_KEY -> publicKey = key.parse(line)
            else -> throw IllegalArgumentException(line)
        }
    }

    override fun toString(): String {
        val sb = StringBuilder().append("[Peer]\n")
        if (!allowedIPsList.isEmpty())
            sb.append(Attribute.ALLOWED_IPS.composeWith(allowedIPsList))
        if (endpoint != null)
            sb.append(Attribute.ENDPOINT.composeWith(endpointString))
        if (persistentKeepalive != 0)
            sb.append(Attribute.PERSISTENT_KEEPALIVE.composeWith(persistentKeepalive))
        if (this.preSharedKey != null)
            sb.append(Attribute.PRESHARED_KEY.composeWith(this.preSharedKey))
        if (this.publicKey != null)
            sb.append(Attribute.PUBLIC_KEY.composeWith(this.publicKey))
        return sb.toString()
    }

    class Observable : BaseObservable, Parcelable {
        private var allowedIPs: String? = null
        private var endpoint: String? = null
        private var persistentKeepalive: String? = null
        private var preSharedKey: String? = null
        private var publicKey: String? = null
        private val interfaceDNSRoutes = ArrayList<String>()
        private var numSiblings: Int = 0

        val canToggleExcludePrivateIPs: Boolean
            @Bindable
            get() {
                val ips = Arrays.asList(*Attribute.stringToList(allowedIPs))
                return numSiblings == 0 && (ips.contains(DEFAULT_ROUTE_V4) || ips.containsAll(
                    DEFAULT_ROUTE_MOD_RFC1918_V4
                ))
            }

        constructor(parent: Peer) {
            loadData(parent)
        }

        private constructor(`in`: Parcel) {
            allowedIPs = `in`.readString()
            endpoint = `in`.readString()
            persistentKeepalive = `in`.readString()
            preSharedKey = `in`.readString()
            publicKey = `in`.readString()
            numSiblings = `in`.readInt()
            `in`.readStringList(interfaceDNSRoutes)
        }

        fun commitData(parent: Peer) {
            parent.allowedIPsString = allowedIPs
            parent.endpointString = endpoint
            parent.persistentKeepaliveString = persistentKeepalive
            parent.preSharedKey = preSharedKey
            parent.publicKey = publicKey
            if (parent.publicKey == null)
                throw IllegalArgumentException(Application.get().getString(R.string.tunnel_error_empty_peer_public_key))
            loadData(parent)
            notifyChange()
        }

        override fun describeContents(): Int {
            return 0
        }

        fun toggleExcludePrivateIPs() {
            val ips = HashSet(Arrays.asList(*Attribute.stringToList(allowedIPs)))
            val hasDefaultRoute = ips.contains(DEFAULT_ROUTE_V4)
            val hasDefaultRouteModRFC1918 = ips.containsAll(DEFAULT_ROUTE_MOD_RFC1918_V4)
            if (!hasDefaultRoute && !hasDefaultRouteModRFC1918 || numSiblings > 0)
                return
            Iterables.removeIf(ips) { ip -> !ip.contains(":") }
            if (hasDefaultRoute) {
                ips.addAll(DEFAULT_ROUTE_MOD_RFC1918_V4)
                ips.addAll(interfaceDNSRoutes)
            } else if (hasDefaultRouteModRFC1918)
                ips.add(DEFAULT_ROUTE_V4)
            setAllowedIPs(Attribute.iterableToString(ips))
        }

        @Bindable
        fun getAllowedIPs(): String? {
            return allowedIPs
        }

        @Bindable
        fun getEndpoint(): String? {
            return endpoint
        }

        @Bindable
        fun getPersistentKeepalive(): String? {
            return persistentKeepalive
        }

        @Bindable
        fun getPreSharedKey(): String? {
            return preSharedKey
        }

        @Bindable
        fun getPublicKey(): String? {
            return publicKey
        }

        private fun loadData(parent: Peer) {
            allowedIPs = parent.allowedIPsString
            endpoint = parent.endpointString
            persistentKeepalive = parent.persistentKeepaliveString
            preSharedKey = parent.preSharedKey
            publicKey = parent.publicKey
        }

        fun setAllowedIPs(allowedIPs: String) {
            this.allowedIPs = allowedIPs
            notifyPropertyChanged(BR.allowedIPs)
            notifyPropertyChanged(BR.canToggleExcludePrivateIPs)
        }

        fun setEndpoint(endpoint: String) {
            this.endpoint = endpoint
            notifyPropertyChanged(BR.endpoint)
        }

        fun setPersistentKeepalive(persistentKeepalive: String) {
            this.persistentKeepalive = persistentKeepalive
            notifyPropertyChanged(BR.persistentKeepalive)
        }

        fun setPreSharedKey(preSharedKey: String) {
            this.preSharedKey = preSharedKey
            notifyPropertyChanged(BR.preSharedKey)
        }

        fun setPublicKey(publicKey: String) {
            this.publicKey = publicKey
            notifyPropertyChanged(BR.publicKey)
        }

        fun setInterfaceDNSRoutes(dnsServers: String?) {
            val ips = HashSet(Arrays.asList(*Attribute.stringToList(allowedIPs)))
            val modifyAllowedIPs = ips.containsAll(DEFAULT_ROUTE_MOD_RFC1918_V4)

            ips.removeAll(interfaceDNSRoutes)
            interfaceDNSRoutes.clear()
            for (dnsServer in Attribute.stringToList(dnsServers)) {
                if (!dnsServer.contains(":"))
                    interfaceDNSRoutes.add("$dnsServer/32")
            }
            ips.addAll(interfaceDNSRoutes)
            if (modifyAllowedIPs)
                setAllowedIPs(Attribute.iterableToString(ips))
        }

        fun setNumSiblings(num: Int) {
            numSiblings = num
            notifyPropertyChanged(BR.canToggleExcludePrivateIPs)
        }

        override fun writeToParcel(dest: Parcel, flags: Int) {
            dest.writeString(allowedIPs)
            dest.writeString(endpoint)
            dest.writeString(persistentKeepalive)
            dest.writeString(preSharedKey)
            dest.writeString(publicKey)
            dest.writeInt(numSiblings)
            dest.writeStringList(interfaceDNSRoutes)
        }

        companion object {
            @JvmField
            val CREATOR: Parcelable.Creator<Observable> = object : Parcelable.Creator<Observable> {
                override fun createFromParcel(`in`: Parcel): Observable {
                    return Observable(`in`)
                }

                override fun newArray(size: Int): Array<Observable?> {
                    return arrayOfNulls(size)
                }
            }

            fun newInstance(): Observable {
                return Observable(Peer())
            }

            private const val DEFAULT_ROUTE_V4 = "0.0.0.0/0"
            private val DEFAULT_ROUTE_MOD_RFC1918_V4 = Arrays.asList(
                "0.0.0.0/5",
                "8.0.0.0/7",
                "11.0.0.0/8",
                "12.0.0.0/6",
                "16.0.0.0/4",
                "32.0.0.0/3",
                "64.0.0.0/2",
                "128.0.0.0/3",
                "160.0.0.0/5",
                "168.0.0.0/6",
                "172.0.0.0/12",
                "172.32.0.0/11",
                "172.64.0.0/10",
                "172.128.0.0/9",
                "173.0.0.0/8",
                "174.0.0.0/7",
                "176.0.0.0/4",
                "192.0.0.0/9",
                "192.128.0.0/11",
                "192.160.0.0/13",
                "192.169.0.0/16",
                "192.170.0.0/15",
                "192.172.0.0/14",
                "192.176.0.0/12",
                "192.192.0.0/10",
                "193.0.0.0/8",
                "194.0.0.0/7",
                "196.0.0.0/6",
                "200.0.0.0/5",
                "208.0.0.0/4"
            )
        }
    }
}
