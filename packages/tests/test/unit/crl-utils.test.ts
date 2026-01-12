import { describe, it, expect } from "vitest";
import { getCRLDistributionPoints } from "../../../core/src/pki/crl-utils.js";
import * as pkijs from "pkijs";

describe("CRL Utilities", () => {
    describe("getCRLDistributionPoints", () => {
        it("should return empty array for certificate without extensions", () => {
            const cert = new pkijs.Certificate();
            cert.extensions = undefined;
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array for certificate without CDP extension", () => {
            const cert = new pkijs.Certificate();
            cert.extensions = [];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array for CDP extension without extnValue", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array when distributionPoints is empty array", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array when distribution point has no distributionPoint field", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [{} as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should extract URL from CRLDistributionPoints with parsedValue", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: [
                        {
                            type: 6,
                            value: "http://crl.example.com/ca.crl",
                        },
                    ],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://crl.example.com/ca.crl"]);
        });

        it("should extract multiple URLs from multiple distribution points", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoints = [
                {
                    distributionPoint: {
                        names: [
                            {
                                type: 6,
                                value: "http://crl1.example.com/ca.crl",
                            },
                        ],
                    },
                },
                {
                    distributionPoint: {
                        names: [
                            {
                                type: 6,
                                value: "http://crl2.example.com/ca.crl",
                            },
                        ],
                    },
                },
            ];

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: mockDistPoints as unknown as pkijs.DistributionPoint[],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([
                "http://crl1.example.com/ca.crl",
                "http://crl2.example.com/ca.crl",
            ]);
        });

        it("should extract URL from parsedValue with alternative structure", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            cdpExt.parsedValue = {
                distributionPoints: [
                    {
                        distributionPoint: {
                            names: [
                                {
                                    type: 6,
                                    value: "http://alt.example.com/crl.crl",
                                },
                            ],
                        },
                    },
                ],
            };
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://alt.example.com/crl.crl"]);
        });

        it("should skip names that are not type 6 (URI)", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: [
                        {
                            type: 2,
                            value: "someDNSName",
                        },
                        {
                            type: 6,
                            value: "http://valid.example.com/crl.crl",
                        },
                        {
                            type: 4,
                            value: "someAddress",
                        },
                    ],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://valid.example.com/crl.crl"]);
        });

        it("should return empty array for empty names array", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: [],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should handle null/undefined names gracefully", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: null,
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array for non-URI type values", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: [
                        {
                            type: 6,
                            value: 12345,
                        },
                    ],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should return empty array for null distribution point", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: null,
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual([]);
        });

        it("should handle multiple extensions and extract CRL from correct one", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    names: [
                        {
                            type: 6,
                            value: "http://correct-crl.example.com/ca.crl",
                        },
                    ],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });

            const otherExt = new pkijs.Extension({
                extnID: "2.5.29.14",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            cert.extensions = [otherExt, cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://correct-crl.example.com/ca.crl"]);
        });

        it("should handle distribution point with '0' key structure containing names array", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    "0": {
                        names: [
                            {
                                type: 6,
                                value: "http://key-zero.example.com/crl.crl",
                            },
                        ],
                    },
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://key-zero.example.com/crl.crl"]);
        });

        it("should handle distribution point with '0' key as array choice", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    "0": [
                        {
                            type: 6,
                            value: "http://array-choice.example.com/crl.crl",
                        },
                    ],
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://array-choice.example.com/crl.crl"]);
        });

        it("should handle distribution point with '0' key having names property", () => {
            const cert = new pkijs.Certificate();
            const cdpExt = new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockDistPoint = {
                distributionPoint: {
                    "0": {
                        names: [
                            {
                                type: 6,
                                value: "http://names-prop.example.com/crl.crl",
                            },
                        ],
                    },
                },
            };

            cdpExt.parsedValue = new pkijs.CRLDistributionPoints({
                distributionPoints: [mockDistPoint as unknown as pkijs.DistributionPoint],
            });
            cert.extensions = [cdpExt];
            const urls = getCRLDistributionPoints(cert);
            expect(urls).toEqual(["http://names-prop.example.com/crl.crl"]);
        });
    });
});
